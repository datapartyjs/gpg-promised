const Hoek = require('@hapi/hoek')
const HoekTransform = require('transform-hoek').transform
const {JSONPath} = require('jsonpath-plus')
const Address = require('email-addresses')
const debug = require('debug')('gpg-parser')

const GpgColons = require('./gpg-colons')
const STATUS_TRANSFORMS = require('./gpg-status-parsers')

const uniqueArray = (arr)=>{
  return arr.filter((v, i, a) => {
    if( v !== undefined && a.indexOf(v) === i){
      return true
    }

    return false
  })
}



  /**
   * Parsers for common GPG inpuut/output formats
   * @class
   */
class GpgParser {
  
  static get DefaultSchema(){
    return GpgColons.DefaultSchema
  }


  static mergeRecord(record, obj){
    const field = record.type

    if(obj[field] === undefined){
      obj[field] = record
    }
    else if(!Array.isArray( obj[field] )){
      obj[field] = [ obj[field], record ]
    }
    else {
      obj[field].push(record)
    }
  }

  static groupRecords(records, schema){

    const output = []
    let depth = []

    for(let idx = 0; idx<records.length; idx++){

      const record = records[idx]

      //debug('group', Object.keys(record))
      if(record == {}){
        debug('group', 'blank')
      }

      if(!record.type){ continue }

      

      //debug('group', record)
      const recDepth = Hoek.reach(schema.types, record.type+'.depth', {default: 0})
      //debug(recDepth, record.type)

      let currentNode = null

      switch(recDepth){
        case 0:
          //! assert depth.length > 0
          debug('group case 0')
          currentNode = depth[ depth.length-1 ]
          //debug('current node', currentNode)
          GpgParser.mergeRecord(record, currentNode)
          break
        case 1:
          currentNode = record
          depth = [ currentNode ]
          output.push(currentNode)
          break
        case 2:
          //debug('depth', depth.length)
          currentNode = record
          depth = [depth[0], currentNode]

          //debug( depth[0])
          //debug(record)

          //debug('group case 2')
          GpgParser.mergeRecord(currentNode, depth[0])
          break
        default:
          throw new Error('gpg record parse error')
      }
    }

    return output
  }

  /**
   * Parses colon-delimited CSV into json and merge related lines into combined objects
   * Useful for decoding content produced by commands using `gpg --with-colons ...`. 
   * See [*gnupg/DETAILS#format-of-the-colon-listings*](https://github.com/CSNW/gnupg/blob/master/doc/DETAILS#format-of-the-colon-listings) for detailed format specification
   * @method
   * @param {string} input 
   * @param {Object} [schema=GpgParser.DefaultSchema] Row header schema 
   */
  static parseColons(input, schema=GpgParser.DefaultSchema){

    //debug(schema)

    const lines = input.split('\n')
    const rows = lines.map(line=>{
      const row = line.split(':')


      const obj = {
        //text: line,
        //fields: row
      }

      const type = row[0]

      //debug('\t',type)

      row.map( (val, idx)=>{
        const fieldMap = Hoek.reach(schema, 'types.'+type+'.fields.'+(idx+1) )
        const col = fieldMap

        if(col && val.length > 0){
          obj[col] = val
        }
      })

      if(obj.type == 'uid'){
        const email = Address.parseOneAddress(obj.user_id)

        if(email){

          obj.name = email.name
          obj.email = email.address
          obj.domain = email.domain
          obj.username = email.local

        }
      }

      return obj
    })


    return GpgParser.groupRecords(rows, schema)
  }

  /**
   * Parse content produced by `gpg --with-colons ...` commands. 
   * See [*gnupg/DETAILS#format-of-the-colon-listings*](https://github.com/CSNW/gnupg/blob/master/doc/DETAILS#format-of-the-colon-listings) for detailed format specification
   * @method
   * @param {string} input
   */
  static parseReaderColons(input){


    const output = {}

    const lines = input.split('\n')
    const rows = lines.map(line=>{
      const row = line.split(':')

      output[row[0]] = row.slice(1)

      /*return {
        name: row[0],
        values: row.slice(1)
      }*/
    })

    return output
  }


  /**
   * GPGStatus with at most one status field
   * @typedef {Object} GPGStatus
   * @property {Object} NEWSIG
   * @property {Object} GOODSIG
   * @property {Object} EXPSIG
   * @property {Object} EXPKEYSIG
   * @property {Object} REVKEYSIG
   * @property {Object} BADSIG
   * @property {Object} ERRSIG
   * @property {Object} VALIDSIG
   * @property {Object} SIG_ID
   * @property {Object} ENC_TO
   * @property {Object} BEGIN_DECRYPTION
   * @property {Object} END_DECRYPTION
   * @property {Object} DECRYPTION_KEY
   * @property {Object} DECRYPTION_INFO
   * @property {Object} DECRYPTION_FAILED
   * @property {Object} DECRYPTION_OKAY
   * @property {Object} SESSION_KEY
   * @property {Object} BEGIN_ENCRYPTION
   * @property {Object} END_ENCRYPTION
   * @property {Object} BEGIN_SIGNING
   * @property {Object} ALREADY_SIGNED
   * @property {Object} SIG_CREATED
   * @property {Object} PLAINTEXT
   * @property {Object} PLAINTEXT_LENGTH
   * @property {Object} ENCRYPTION_COMPLIANCE_MODE
   * @property {Object} DECRYPTION_COMPLIANCE_MODE
   * @property {Object} VERIFICATION_COMPLIANCE_MODE
   * @property {Object} KEY_CONSIDERED
   * @property {Object} KEYEXPIRED
   * @property {Object} KEYREVOKED
   * @property {Object} NO_PUBKEY
   * @property {Object} NO_SECKEY
   * @property {Object} KEY_CREATED
   * @property {Object} KEY_NOT_CREATED
   * @property {Object} TRUST_UNDEFINED
   * @property {Object} TRUST_NEVER
   * @property {Object} TRUST_MARGINAL
   * @property {Object} TRUST_FULLY
   * @property {Object} TRUST_ULTIMATE
   * @property {Object} GOODMDC
   * @property {Object} FAILURE
   * @property {Object} SUCCESS
   * @property {Object} WARNING
   * @property {Object} ERROR
   * @property {Object} CARDCTRL
   * @property {Object} SC_OP_FAILURE
   * @property {Object} SC_OP_SUCCESS
   * @property {Object} INV_RECP
   * @property {Object} INV_SGNR
   * @property {Object} IMPORTED
   * @property {Object} IMPORT_OK
   * @property {Object} IMPORT_PROBLEM
   * @property {Object} IMPORT_RES
   * @property {Object} EXPORTED
   * @property {Object} EXPORT_RES
   */

  /** 
   * GPG Status stream parsed 
   * @typedef {Array.<GPGStatus>} GPGStatusArray
   */



  /**
   * Parses space-delimited CSV into json objects
   * Useful for decoding content produced by commands using `gpg --status-fd N ...`. 
   * See [*gnupg/DETAILS#format-of-the-status-fd-output*](https://github.com/CSNW/gnupg/blob/master/doc/DETAILS#format-of-the-status-fd-output) for detailed format specification
   * @method
   * @param {string} input Input string
   * @returns {GPGStatusArray}
   */
  static parseStatusFd(input){
    const lines = input.split('\n')
    const statusLines = lines.filter(line=>{
      return line.startsWith('[GNUPG:]')
    })

    const status = statusLines.map(statusLine=>{
      const [prefix, keyword, ...args] = statusLine.split(' ')

      const input = { keyword, args }

      const obj = {}

      const transform = STATUS_TRANSFORMS[keyword]
      if(transform instanceof Function){
        debug('using parser', keyword)
        obj[keyword] = transform(input)
      }
      else if(transform){
        debug('using transform', keyword)
        obj[keyword] = HoekTransform(input, transform)
      }
      else{
        obj.input = input
      }

      return obj
    })

    return status
  }


  /**
   * @method
   * @param {GPGStatusArray} status
   * @param {string} keyword
   * @returns {boolean}
   */
  static Status_HasKeyword = (status, keyword)=>{
    const exists = (JSONPath({
      path: `$..${keyword}`,
      json: status
    }) || [])[0]

    if(exists){ return true }
    return false
  }

  /**
   * @method
   * @param {GPGStatusArray} status
   */
  static Status_GetImportedKeys = (status)=>{
    return uniqueArray(
      JSONPath({
        path: '$..IMPORT_OK.fingerprint',
        json: status
      }) || []
    )
  }

  /**
   * @method
   * @param {GPGStatusArray} status
   * @returns {string} Primary fingerprint
   */
  static Status_GetSigPrimaryFpr = (status)=>{
    const sigFpr = (JSONPath({
        path: '$..VALIDSIG.primary_key_fpr',
        json: status
      }) || [])
    
    return sigFpr[0]
  }

  /**
   * @method
   * @param {GPGStatusArray} status
   * @param {string[]} allowed List of allowed uid, fpr or keyid
   */
  static Status_AssertSignatureAllowed(status, allowed=[]){
    if(!GpgParser.Status_IsSignerAllowed(status,allowed)){ 
      throw new Error('Signer not allowed')
    }
  }

  /**
   * Decrypt cipher text
   * @method
   * @param {GPGStatusArray} status
   * @param {Object} options
   * @param {Object} options.level Acceptable signer trust levels. Trust level of a specific signature is computed with respect to configured trust model
   * @param {boolean} options.level.none      Accept signers with no trust
   * @param {boolean} options.level.unknown   Accept signers with unknown/undefined trust
   * @param {boolean} options.level.never     Accept untrustowrthy signers, potentially with revoked or bad keys
   * @param {boolean} options.level.marginal  Accept signers with marginal trust
   * @param {boolean} options.level.full      Accept signers with full trust
   * @param {boolean} options.level.ultimate  Accept signers with ultimate trust
   * @param {Object} options.allow Acceptable signature/signer expiry/revoke status
   * @param {boolean} options.allow.allow_expired_sig Accept expired signatures
   * @param {boolean} options.allow.allow_expired_key Accept expired signer key
   * @param {boolean} options.allow.allow_revoked_key Accept revoked signer key
   */
  static Status_AssertSignatureTrusted(status, {
      none=false,
      unknown=false,
      never= false,
      marginal=true,
      full=true,
      ultimate=true
    }={}, {
      allow_expired_sig=false,
      allow_expired_key=false,
      allow_revoked_key=false
    }={}
  ){

    // Check signature/signer status messages
    let goodness = GpgParser.Status_IsSigGood(status)

    if(allow_expired_sig==true){
      goodness |= GpgParser.Status_IsSigExpired(status)
    }

    if(allow_expired_key==true){
      goodness |= GpgParser.Status_IsSigKeyExpired(status)
    }

    if(allow_revoked_key==true){
      goodness |= GpgParser.Status_IsSigKeyRevoked(status)
    }


    // Check signer trustyness
    let trustyness = false
    
    if(unknown==true){
      trustyness |= GpgParser.Status_IsSigTrustUnknown(status)
    }

    if(marginal==true){
      trustyness |= GpgParser.Status_IsSigTrustMarginal(status)
    }

    if(full==true){
      trustyness |= GpgParser.Status_IsSigTrustFully(status)
    }

    if(ultimate==true){
      trustyness |= GpgParser.Status_IsSigTrustUltimate(status)
    }

    if(never==true){
      debug('WARNING - TRUST_NEVER allowed in signature verification')
      console.log('WARNING - TRUST_NEVER allowed in signature verification')
      trustyness |= GpgParser.Status_IsSigTrustNever(status)
    }
    else{
      trustyness &= !GpgParser.Status_IsSigTrustNever(status)
    }

    const goodReason = GpgParser.Status_GetSigResult(status)
    const trustReason = GpgParser.Status_GetSigTrustResult(status)

    if(trustReason === undefined && none === true){
      debug('WARNING - TRUST_NONE allowed in signature verification')
      console.log('WARNING - TRUST_NONE allowed in signature verification')
      trustyness = true
    }
    

    debug('AssertSignatureTrusted - validating signature [',goodReason, trustReason,']')

    if(!goodness){
      throw new Error('Signature rejected - '+goodReason)
    }
    
    if(!trustyness){      
      throw new Error('Signature not trusted - '+trustReason)
    }

    debug('AssertSignatureTrusted - signature appears good and trusted [',goodReason, trustReason,']')
    
  }

  /**
   * @method
   * @param {GPGStatusArray} status
   * @returns {string}
   */
  static Status_GetSigResult = (status)=>{
    if(GpgParser.Status_IsSigGood(status)){ return 'GOODSIG' }
    if(GpgParser.Status_IsSigBad(status)){ return 'BADSIG' }
    if(GpgParser.Status_IsSigError(status)){ return 'ERRSIG' }
    if(GpgParser.Status_IsSigExpired(status)){ return 'EXPSIG' }
    if(GpgParser.Status_IsSigKeyExpired(status)){ return 'EXPKEYSIG' }
    if(GpgParser.Status_IsSigKeyRevoked(status)){ return 'REVKEYSIG' }
    return undefined
  }

  /**
   * @method
   * @param {GPGStatusArray} status
   * @returns {string}
   */
  static Status_GetSigTrustResult = (status)=>{
    if(GpgParser.Status_IsSigTrustUnknown(status)){ return 'TRUST_UNDEFINED' }
    if(GpgParser.Status_IsSigTrustNever(status)){ return 'TRUST_NEVER' }
    if(GpgParser.Status_IsSigTrustMarginal(status)){ return 'TRUST_MARGINAL' }
    if(GpgParser.Status_IsSigTrustFully(status)){ return 'TRUST_FULLY' }
    if(GpgParser.Status_IsSigTrustUltimate(status)){ return 'TRUST_ULTIMATE' }
    return undefined
  }

  /**
   * @method
   * @param {GPGStatusArray} status
   * @returns {boolean}
   */
  static Status_IsSigGood = (status)=>{
    return GpgParser.Status_HasKeyword(status, 'GOODSIG')
  }

  /**
   * @method
   * @param {GPGStatusArray} status
   * @returns {boolean}
   */
  static Status_IsSigBad = (status)=>{
    return GpgParser.Status_HasKeyword(status, 'BADSIG')
  }

  /**
   * @method
   * @param {GPGStatusArray} status
   * @returns {boolean}
   */
  static Status_IsSigError = (status)=>{
    return GpgParser.Status_HasKeyword(status, 'ERRSIG') 
  }

  /**
   * @method
   * @param {GPGStatusArray} status
   * @returns {boolean}
   */
  static Status_IsSigExpired = (status)=>{
    return GpgParser.Status_HasKeyword(status, 'EXPSIG')
  }

  /**
   * @method
   * @param {GPGStatusArray} status
   * @returns {boolean}
   */
  static Status_IsSigKeyExpired = (status)=>{
    return GpgParser.Status_HasKeyword(status, 'EXPKEYSIG')
  }

  /**
   * @method
   * @param {GPGStatusArray} status
   * @returns {boolean}
   */
  static Status_IsSigKeyRevoked = (status)=>{
    return GpgParser.Status_HasKeyword(status, 'REVKEYSIG')
  }

  /**
   * @method
   * @param {GPGStatusArray} status
   * @returns {boolean}
   */
  static Status_IsSigTrustUnknown = (status)=>{
    return GpgParser.Status_HasKeyword(status, 'TRUST_UNDEFINED')
  }

  /**
   * @method
   * @param {GPGStatusArray} status
   * @returns {boolean}
   */
  static Status_IsSigTrustNever = (status)=>{
    return GpgParser.Status_HasKeyword(status, 'TRUST_NEVER')
  }

  /**
   * @method
   * @param {GPGStatusArray} status
   * @returns {boolean}
   */
  static Status_IsSigTrustMarginal = (status)=>{
    return GpgParser.Status_HasKeyword(status, 'TRUST_MARGINAL')
  }

  /**
   * @method
   * @param {GPGStatusArray} status
   * @returns {boolean}
   */
  static Status_IsSigTrustFully = (status)=>{
    return GpgParser.Status_HasKeyword(status, 'TRUST_FULLY')
  }

  /**
   * @method
   * @param {GPGStatusArray} status
   * @returns {boolean}
   */
  static Status_IsSigTrustUltimate = (status)=>{
    return GpgParser.Status_HasKeyword(status, 'TRUST_ULTIMATE')
  }

  /**
   * @method
   * @param {GPGStatusArray} status
   * @param {string[]} allowed List of allowed uid, fpr or keyid
   * @returns {boolean}
   */
  static Status_IsSignerAllowed = (status, allowed)=>{
    const fpr = GpgParser.Status_GetSigPrimaryFpr(status)

    debug('IsSignerAllowed', allowed, fpr)

    if(fpr.length > 0 && Array.isArray(allowed) && allowed.length > 0 && allowed.indexOf(fpr) > -1){
      debug('\tallowed')
      return true
    }

    debug('\tnot allowed')
    return false
  }
}

module.exports = GpgParser