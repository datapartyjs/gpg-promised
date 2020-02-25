const fs = require('fs')
const tmp = require('tmp')
const path = require('path')
const mkdirp = require('mkdirp')
const Hoek = require('@hapi/hoek')
const {JSONPath} = require('jsonpath-plus')

const GpgParser = require('./gpg-parser')
const KeyServerClient = require('./key-server-client')

const debug = require('debug')('gpg-promised.KeyChain')

const DEFAULT_AGENT_CONFIG=`enable-ssh-support
default-cache-ttl 1800
max-cache-ttl 7200
`

const uniqueArray = (arr)=>{
  return arr.filter((v, i, a) => {
    if( v !== undefined && a.indexOf(v) === i){
      return true
    }

    return false
  })
}

const exec = require('./shell').exec

class KeyChain {

  /**
   * A GPG keychain
   * @class
   * @constructor
   * @param {string} homedir Path to use as GPG homedir. Defaults to a tmp directory. See {@link https://github.com/raszi/node-tmp/blob/master/README.md|node-tmp} for more info on temp folder creation.
   */

  constructor(homedir){
    this.homedir = homedir
    this.temp = null
  }

  static get GpgParser(){
    return GpgParser
  }

  /**
   * Open or create the GPG keychain
   * @method
   */

  async open(){

    if(!this.homedir){
      //use temp directory
      this.temp = tmp.dirSync()
      this.homedir = this.temp.name
      debug('using temp directory -', this.temp.name)
    }

    if(!path.isAbsolute(this.homedir)){
      throw new Error('path must be absolute')
    }

    if(!fs.existsSync(this.homedir)){
      debug('creating dir -', this.homedir)
      //create directory

      mkdirp.sync(this.homedir, '0700' )
    }

    if(!fs.existsSync(this.homedir + '/gpg-agent.conf')){
      debug('write default gpg-agent.conf')
      fs.writeFileSync(this.homedir + '/gpg-agent.conf', DEFAULT_AGENT_CONFIG)
    }
  }


  /**
   * Call a GPG command
   * @method
   * @param {string} input STDIN input text
   * @param {Array(string)} args Command line arguments
   * @param {boolean} nonbatch Do not use the `--batch` flag
   * @returns {ExecResult}
   */
  async call(input, args, nonbatch=false){
    const gpgArgs = ['--homedir', this.homedir, (nonbatch!=true) ? '--batch' : undefined  ].concat(args)

    debug('call -', gpgArgs)
    const result = await exec('gpg '+gpgArgs.join(' '), undefined, input)

    return result
  }

  /**
   * Check if a secure card is inserted
   * @method
   * @returns {boolean}
   */
  async hasCard(){
    
    try{
      const cardStatus = await this.cardStatus()
    }
    catch(err){
      debug('hasCard - false - err -', err)
      return false
    }

    return true
  }

  /**
   * Is the inserted secure card set to owner trust
   * @method
   * @returns {boolean}
   */
  async isCardTrusted(){
    
    if(! (await this.hasCard()) ){
      throw new Error('Insert card')
    }

    const cardStatus = await this.cardStatus()
    const fingerprint = (cardStatus.fpr[0] || '').toLowerCase()

    debug('cardStatus',cardStatus)

    const secrets = await this.listSecretKeys(true)
    debug(JSON.stringify( secrets, null, 2) )

    const cardKey = KeyChain.getKeyBySubKeyId(secrets, fingerprint)
    debug('cardKey', cardKey)

    if(!cardKey){
      return false
    }

    const match = KeyChain.isKeyFromCard(cardKey, cardStatus)

    if(!match){
      throw new Error('Card does not match secret key')
    }

    return true
  }

  /**
   * Retrieve secure card metadata
   * @method
   * @returns {Object}
   */
  async cardStatus(){
    debug('cardStatus')
    const command = ['--card-status', '--with-colons', '--with-fingerprint']

    const response = await this.call('', command)
    const list = response.stdout.toString()

    debug(response.stderr.toString())

    debug('\t'+list)
    const status = GpgParser.parseReaderColons(list)
    debug('card status', status)
    return status
  }

  /**
   * Trust the currently inserted secure card
   * @method
   */
  async trustCard(){
    
    if(await this.isCardTrusted()){
      debug('card already trusted')
      return
    }

    const cardStatus = await this.cardStatus()
    const subFingerprint = (cardStatus.fpr[0] || '').toLowerCase()

    debug('trustCard card status', cardStatus)
    debug('trustCard sub fpr', subFingerprint)

    await this.recvKey(subFingerprint)

    const publics = await this.listPublicKeys()
    const cardKey = KeyChain.getKeyBySubKeyId(publics, subFingerprint, 'sub')

    if(!cardKey){ throw new Error('Card key not found') }

    debug('trustCard', cardKey)
    const fingerprint = Hoek.reach(cardKey.fpr, '0.user_id')

    if(!fingerprint){ throw new Error('Could not find key by subkey fingerprint', subFingerprint) }

    debug('trustCard fpr', fingerprint)

    await this.trustKey(fingerprint, '5')

  }

  /**
   * Import the supplied key with owner trust
   * @method
   * @param {string} keyId Fingerprint/grip/email of desired key
   * @param {string} level Trust level code (1 - 5)
   */
  async trustKey(keyId, level){
    debug('trust', keyId, level)

    const trustText = (await this.call('', ['--export-ownertrust'])).stdout.toString()
    const trust = '' + trustText + keyId+':' +(parseInt(level)+1)+ ':\n'
    const command = ['--import-ownertrust' ]
    const result = (await this.call(trust, command))

    debug('updating trustdb')
    debug('trustKey out', result.stdout.toString())
    debug('trustKey err', result.stderr.toString())
  }

  /**
   * Lookup keys. This uses the {@link KeyServerClient} rather than GPG to ensure we don't accidently modify the keychain
   * @method 
   * @param {string} text Search text {@link HKPIndexSchema}
   * @param {boolean} exact Exact matches only
   * @param {string} [server=KeyServerClient.Addresses.ubuntu]
   * @returns {string} Parsed csv-to-json search results
   */
  async lookupKey(text, exact=false, keyserver=KeyServerClient.Addresses.ubuntu){
    const hkpClient = new KeyServerClient(keyserver)
    
    const result = await hkpClient.search(text)

    if(result.length > 1 && result[0].type == 'info'){
      return result[1]
    }

    return result
  }

  /**
   * Recieve key specified by fingerprint
   * @method
   * @param {string} fingerprint Fingerpint/email/grip of key to recieve
   * @param {string} [server=hkps://keyserver.ubuntu.com:443]
   */
  async recvKey(fingerprint, server='hkps://keyserver.ubuntu.com:443'){
    const command = ['--status-fd 2', '--keyserver', server, '--recv-keys', fingerprint]
    const response = await this.call('', command)

    const output = GpgParser.parseReaderColons(response.stdout.toString())
    const status = GpgParser.parseStatusFd(response.stderr.toString())
    debug('recvKey output', output)
    debug('recvKey status', status)
  }

  /**
   * Transmit 
   * @param {string} [server=hkps://keyserver.ubuntu.com:443]
   * @param {string} fpr 
   */
  async sendKeys(fpr, server='hkps://keyserver.ubuntu.com:443'){
    const command = ['--keyserver', server, '--send-keys']

    if(fpr){
      command.push(fpr)
    }

    await this.call('', command)
    return
  }

  /**
   * Refresh keyring public keys from specified server
   * @param {string} [server=hkps://keyserver.ubuntu.com:443]
   */
  async refreshKeys(server='hkps://keyserver.ubuntu.com:443'){
    const command = ['--keyserver', server, '--refresh-keys']

    await this.call('', command)
    return
  }

  /**
   * Sign a key
   * @param {string} to 
   * @param {string} from 
   */
  async signKey(to, from){
    debug('signKey -',to, '<', from)
    const command = ['--command-fd 0', '--status-fd 2', '--edit-key', to]

    if(from){
      command.unshift('--local-user', from)
    }

    const result = await this.call('sign\n'+'y\nsave\nquit\n', command, false)

    debug('signKey out', result.stdout.toString())
    debug('signKey err', result.stderr.toString())

    return
  }


  /**
   * Create public/private key pair
   * @method
   * @param {Object} options
   * @param {string} options.email
   * @param {string} options.name
   * @param {string} options.expire
   * @param {string} options.passphrase
   * @param {string} [options.keyType=RSA]
   * @param {string} [options.keySize=4096]
   * @param {string} [options.unattend=false]
   */
  async generateKey({email, name, expire=0, passphrase, keyType='RSA', keySize=4096, unattend=false}){
    const command = ['--generate-key']

    //! https://www.gnupg.org/documentation/manuals/gnupg/Unattended-GPG-key-generation.html
    let statements = 'Key-Type: ' + keyType + '\n' +
      'Key-Length: ' + keySize + '\n' +
      'Name-Real: ' + name + '\n' +
      'Name-Email: ' + email + '\n' +
      'Expire-Date: ' + expire + '\n'

    if (passphrase && passphrase.length > 0 && !unattend) {

      statements += 'Passphrase: ' + passphrase + '\n'

    } else if (unattend && !passphrase) {

      statements += '%no-protection' + '\n'

    } else {
      throw new Error('unsupported passphrase/unattend setting')
    }

    statements += '%commit' + '\n' + '%echo done' + '\n'

    const result = (await this.call(statements, command)).stdout.toString()

    debug('genkey', result)
  }

  /**
   * Export ascii armor PGP public key
   * @param {string} keyId
   * @returns {string}
   */
  async exportPublicKey(keyId){
    const command = ['--armor', '--status-fd 2', '--export', keyId]
    const result = await this.call('', command)

    debug('exportKey stdout -', result.stdout.toString())
    debug('exportKey stderr -', result.stderr.toString())

    return result.stdout.toString()
  }

  /**
   * Export ascii armor PGP secret key
   * @param {string} keyId
   * @returns {string}
   */
  async exportSecretKey(keyId){
    const command = ['--armor', '--status-fd 2', '--export-secret-keys', keyId]
    const result = await this.call('', command)

    debug('exportSecretKey stdout -', result.stdout.toString())
    debug('exportSecretKey stderr -', result.stderr.toString())

    return result.stdout.toString()
  }


  /**
   * Import PGP key
   * @param {string} key
   * @returns {boolean}
   */
  async importKey(key){
    const command = ['--status-fd 2', '--import']
    const result = await this.call(key, command)

    debug('importKey stdout -', result.stdout.toString())
    debug('importKey stderr -', result.stderr.toString())

    const status = GpgParser.parseStatusFd(result.stderr.toString())

    let imported = GpgParser.Status_GetImportedKeys(status)

    debug('imported keys', imported)

    return imported
  }

  /**
   * Encrypt, sign, and armor input
   * @method
   * @param {string} input 
   * @param {Array(string)} to List of keyid, fpr or uid of message recipients
   * @param {string} from Local keyid or uid to use in message signing
   * @param {('pgp'|'classic'|'tofu'|'tofu+pgp'|'direct'|'always'|'auto')} [options.trust=pgp] Trust model See [`gpg --trust-model`](https://www.gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html#index-trust_002dmodel)
   * @returns {string} ciphertext
   */
  async encrypt(input, to, from, trust='pgp'){
    const command = ['--encrypt', '--sign', '--armor', '--status-fd 2', '--trust-model', trust]

    if(from){
      command.push('--local-user')
      command.push(from)
    }

    if(to && to.length>0){
      to.map( id=>{
        command.push('--recipient')
        command.push(id)
      })
    }


    const result = await this.call(input, command)
    
    const stdout = result.stdout.toString()
    const stderr = result.stderr.toString()

    debug('enc output', stdout)
    debug('enc status', stderr)
    debug('enc status obj', GpgParser.parseStatusFd(stderr))
    return stdout
  }

  /**
   * Decrypt cipher text
   * @method
   * @param {string} input 
   * @param {Object} options
   * @param {string[]} options.from List of keyid, fpr or uid(email) of allowed message signers. Defaults to allowing any trusted signer
   * @param {('pgp'|'classic'|'tofu'|'tofu+pgp'|'direct'|'always'|'auto')} [options.trust=pgp] Trust model See [`gpg --trust-model`](https://www.gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html#index-trust_002dmodel)
   * @param {Object} options.level Acceptable signer trust levels. Trust level of a specific signature is computed with respect to configured trust model
   * @param {boolean} [options.level.none=false]      Accept signers with no trust
   * @param {boolean} [options.level.unknown=false]   Accept signers with unknown/undefined trust
   * @param {boolean} [options.level.never=false]     Accept untrustowrthy signers, potentially with revoked or bad keys
   * @param {boolean} [options.level.marginal=true]  Accept signers with marginal trust
   * @param {boolean} [options.level.full=true]      Accept signers with full trust
   * @param {boolean} [options.level.ultimate=true]  Accept signers with ultimate trust
   * @param {Object} options.allow Acceptable signature/signer expiry/revoke status
   * @param {boolean} [options.allow.allow_expired_sig=false] Accept expired signatures
   * @param {boolean} [options.allow.allow_expired_key=false] Accept expired signer key
   * @param {boolean} [options.allow.allow_revoked_key=false] Accept revoked signer key
   * @returns {Buffer}
   */
  async decrypt(input, {
    from=[], trust='pgp', level, allow
  }={}){
    const command = ['--decrypt','--status-fd 2', '--trust-model '+trust]

    const result = await this.call(input, command)
    
    const stdout = result.stdout
    const stderr = result.stderr.toString()
    const status = GpgParser.parseStatusFd(stderr)

    debug('dec output', stdout)
    debug('dec status', JSON.stringify(status,null,2))

    const validFpr = JSONPath({
      json: status,
      path:'$..VALIDSIG.primary_key_fpr'
    })[0]

    debug(validFpr)

    
    if(!Array.isArray(from) && from.length > 0){
      from = [from]
    }
    else if(!from || (Array.isArray(from) && from.length < 1)){
      from = [validFpr]
    }

    // query public keys using from list
    // filter public key list to top level keyid
    // merge original from and keyid list
    // filter for uniqueness

    const emails = from.filter((val)=>{ return val.indexOf('@') > -1 })
    if(emails.length > 0){

      const emailKeyList = await this.listPublicKeys(false, emails.join(' '))
      debug(emailKeyList)
      const emailFingerprintList = []
      
      emailKeyList.map(key=>{ 

        if(!Array.isArray(key.fpr)){
          emailFingerprintList.push( Hoek.reach(key, 'fpr.user_id') )
        }
        else{
          key.fpr.map(subKey=>{
            emailFingerprintList.push( subKey.user_id )
          })
        }
      })

      from = uniqueArray(from.concat(emailFingerprintList))

    }

    debug('allowed from', from)

    GpgParser.Status_AssertSignatureAllowed(status, from)
    GpgParser.Status_AssertSignatureTrusted(status, level, allow)

    return stdout
  }

  /**
   * @method
   * @param {string} input 
   * @param {string} sender 
   */
  async verify(input, sender){
    throw new Error('not implemented')
    //const command = ['--logger-fd', '1', '--verify']
    const command = ['--list-packets']

    const result = (await this.call(input, command, true)).stdout.toString()

    debug('verify data', result)
    return result
  }

  /**
   * List of `uid.email` for every secret key with owner trust
   * @returns {Array(string)}
   */
  async whoami(){
    const primary = await this.listSecretKeys(true)

    const handles = primary.map(rec=>{
      return Hoek.reach(rec, 'uid.email')
    })

    if(handles.length < 1 || !handles[0]){
      debug('handles.length', handles.length)
      throw new Error('no primary identity')
    }

    return handles
  }

  /**
   * List of secret keys
   * @param {boolean} ultimate Only list keys with owner trust
   * @param {string}  keyId Query text, accepts keyid, fingerprints or email addresses
   * @returns {Array(Objects)} Parsed gpg output packets
   */
  async listSecretKeys(ultimate=true, keyId){
    const command = ['--list-secret-keys', '--with-colons', '--with-fingerprint', keyId]
    const list = (await this.call('', command)).stdout.toString()

    return GpgParser.parseColons(list).filter((record)=>{
      return record.type == 'sec' && (!ultimate ? true : ( record.validity == 'u' ))
    })
  }

  /**
   * List of public keys
   * @param {boolean} ultimate Only list keys with owner trust
   * @param {string}  keyId Query text, accepts keyid, fingerprints or email addresses
   * @returns {Array(Objects)} Parsed gpg output packets
   */
  async listPublicKeys(ultimate=false, keyId){
    const command = ['--list-public-keys', '--with-colons', '--with-fingerprint', keyId]
    const list = (await this.call('', command)).stdout.toString()

    return GpgParser.parseColons(list).filter((record)=>{
      return record.type == 'pub' && (!ultimate ? true : ( record.validity == 'u' ))
    })
  }

  /**
   * Encrypt/decrypt gpgtar files
   * @param {Object} options
   * @property {string} cwd
   * @property {string} outputPath
   * @property {string} to
   * @property {string} sign
   * @property {string} encrypt
   * @property {string} decrypt
   * @property {string} extractPath
   * @property {string} inputPaths
   * @Returns {ExecResult}
   */
  async tar({cwd, outputPath, to, sign, encrypt, decrypt, extractPath, inputPaths}){
    
    const command = ['gpgtar']

    if(sign){ command.push('-s') }
    if(encrypt){ command.push('-e') }
    if(decrypt){
      command.push('-d')
      if(extractPath){ command.push(' --directory ' + extractPath) }
    }

    if(outputPath){ command.push(' --output ' + outputPath) }

    if(to){
      if(Array.isArray(to)){ command.push( to.map(t=>{return '-r '+t}).join(' ') ) }
      else{ command.push('-r '+to) }

      command.push( inputPaths.join(' ') )
    }

    const cmdStr = command.join(' ')

    debug('gpgtar - [', cmdStr, ']')
    return await exec(cmdStr, {
      cwd,
      env: {
        GNUPGHOME: this.homedir
      }
    })
  }



  /**
   * Find a key based on id of a sub-key
   * @param {Array(Object)} list List of parsed GPG output packets
   * @param {string} sub_key_id Sub key id to search for
   * @param {*} subField Subkey field (typically ssb or sub)
   * @returns {Object} Parsed key from GPG output packets
   */
  static getKeyBySubKeyId(list, sub_key_id, subField = 'ssb'){
    debug('getKeyBySubKeyId', sub_key_id)
    let result = null
    list.map( key => {

      let subKeys = key[subField]

      if(!Array.isArray(subKeys)){
        subKeys = [subKeys]
      }

      subKeys.map( subkey => {

        const keyIdLen = subkey.keyid.length
        const matchIdx = sub_key_id.toLowerCase().indexOf(subkey.keyid.toLowerCase())
        const matchLen = (matchIdx > -1) ? sub_key_id.length - matchIdx : 0

        if( keyIdLen == matchLen ){
          result = key
        }
      })
    } )

    return result
  }

  /**
   * Find a key by a field value
   * @param {Array(Object)} list List of parsed GPG output packets
   * @param {string} field Name/path to field
   * @param {string} value
   * @returns {Object} Parsed key from GPG output packets
   */
  static getKeyByField(list, field, value){
    let result = []
    list.map( key => {

      const fieldVal = Hoek.reach(key, field)

      if(fieldVal == value){
        result.push(key)
      }
    })

    return result
  }
  
  /**
   * Check if the specified secure card matches the supplied key
   * @param {Object} key A parsed key with ssb field
   * @param {Object} cardInfo Card info from {@link KeyChain.cardStatus}
   */
  static isKeyFromCard(key, cardInfo){
    debug('isKeyFromCard', key, cardInfo)
    let snMatch = false

    const cardSN = cardInfo.Reader[ cardInfo.Reader.length - 3 ]

    debug('cardSN', cardSN)

    key.ssb.map( subkey =>{
      const sn = subkey.token_sn

      if(sn == cardSN){
        snMatch = true
      }
    })

    return snMatch

  }


  /**
   * Find a subkey id with specific capabilities
   * @param {Object} key 
   * @param {string} cap Capabilities (a, c, e, d)
   * @param {string} subField Field name/path
   * @returns {Array(string)} List of subkey ids
   */
  static getSubKeyIdByCapability(key, cap, subField='ssb'){
    debug('getSubKeyIdByCapability', key, cap, subField)
    const ids = []
    const subKeys = key[subField]

    subKeys.map( subkey => {
      if(subkey.key_cap == cap){
        ids.push(subkey.keyid)
      }
    })

    return ids
  }
}

module.exports = KeyChain
