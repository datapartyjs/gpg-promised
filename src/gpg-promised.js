const GPG = require('gpg')
const util = require('util')
const Address = require('email-addresses')
const debug = require('debug')('gpg-promised')

const exec = require('./shell').exec

exports.call = async (input, args)=>{
  return new Promise((resolve, reject)=>{

    GPG.call(input, args, (err, stdout, stderr)=>{
      if(err){ return reject(err) }

      resolve({
        stdout,
        stderr
      })
    })

  })
}

const COLONS_FIELD_MAP = {
  1: 'type',
  2: 'validity',
  3: 'key_length',
  4: 'public_key_algo',
  5: 'key_id',
  6: 'creation_date',
  7: 'expiry_date',
  8: 'certsn_uidhash_siginfo',
  9: 'owner_trust',
  10: 'user_id',
  11: 'sig_class',
  12: 'key_cap',
  13: 'issuercertfpr_otherinfo',
  14: 'flags',
  15: 'token_sn',
  16: 'hash_algo',
  17: 'curve_name',
  18: 'compliance_flags',
  19: 'last_update',
  20: 'origin',
  21: 'comment'
}

const RECORD_DEPTH = {
  'tru': 1,
  'sec': 1,
  'pub': 1,
  'ssb': 2,
  'sub': 2
}

function mergeRecord(record, obj){
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

exports.groupRecords = (records)=>{

  const output = []
  let depth = []

  for(let idx = 0; idx<records.length; idx++){

    const record = records[idx]

    if(!record.type){ continue }

    const recDepth = RECORD_DEPTH[record.type] || 0
    debug(recDepth, record.type)

    let currentNode = null

    switch(recDepth){
      case 0:
        //! assert depth.length > 0
        currentNode = depth[ depth.length-1 ]
        mergeRecord(record, currentNode)
        break
      case 1:
        currentNode = record
        depth = [ currentNode ]
        output.push(currentNode)
        break
      case 2:
        debug('depth', depth.length)
        currentNode = record
        depth = [depth[0], currentNode]

        debug( depth[0])
          debug(record)

        mergeRecord(currentNode, depth[0])
        break
      default:
        throw new Error('gpg record parse error')
    }
  }

  return output
}

exports.parseColons = (input)=>{
  const lines = input.split('\n')
  const rows = lines.map(line=>{
    const row = line.split(':')


    const obj = {
      //text: line,
      //fields: row
    }

    row.map( (val, idx)=>{
      const col = COLONS_FIELD_MAP[idx+1]

      if(col && val.length > 0){
        obj[col] = val
      }
    })

    if(obj.type == 'uid'){
      const email = Address.parseOneAddress(obj.user_id)

      obj.name = email.name
      obj.email = email.address
      obj.domain = email.domain
      obj.username = email.local
    }

    return obj
  })

  return exports.groupRecords(rows)
}

exports.callStreaming = util.promisify(GPG.callStreaming)


exports.listSecretKeys = async (ultimate=true)=>{
  const command = ['--list-secret-keys', '--with-colons', '--with-fingerprint']
  const list = (await exports.call('', command)).stdout.toString()

  return exports.parseColons(list).filter((record)=>{
    return record.type == 'sec' && (!ultimate ? true : ( record.validity == 'u' ))
  })
}

exports.listPublicKeys = async (ultimate=false)=>{
  const command = ['--list-public-keys', '--with-colons', '--with-fingerprint']
  const list = (await exports.call('', command)).stdout.toString()

  return exports.parseColons(list).filter((record)=>{
    return record.type == 'pub' && (!ultimate ? true : ( record.validity == 'u' ))
  })
}

exports.whoami = async ()=>{
  const primary = await exports.listSecretKeys(true)

  const handles = primary.map(rec=>{
    return rec.uid.email
  })

  if(handles.length < 1 || !handles[0]){
    throw new Error('no primary identity')
  }

  return handles
}

exports.tar = async ({ cwd, outputPath, to, sign, encrypt, decrypt, extractPath, inputPaths })=>{

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
  return await exec(cmdStr, {cwd})
}