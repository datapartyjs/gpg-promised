const Hoek = require('@hapi/hoek')
const Address = require('email-addresses')
const debug = require('debug')('gpg-parser')

const COLONS_FIELD_MAP = {
  1: 'type',
  2: 'validity',
  3: 'key_length',
  4: 'public_key_algo',
  5: 'keyid',
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

const DefaultSchema = {
  types: {
    tru: {
      depth: 1,
      fields: COLONS_FIELD_MAP
    },
    sec: {
      depth: 1,
      fields: COLONS_FIELD_MAP
    },
    pub: {
      depth: 1,
      fields: COLONS_FIELD_MAP
    },
    ssb: {
      depth: 2,
      fields: COLONS_FIELD_MAP
    },
    sub: {
      depth: 2,
      fields: COLONS_FIELD_MAP
    },
    fpr: {
      depth: 2,
      fields: COLONS_FIELD_MAP
    },
    uid: {
      depth: 2,
      fields: COLONS_FIELD_MAP
    },
  }
}

exports.DefaultSchema = DefaultSchema

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

exports.groupRecords = (records, schema)=>{

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
        mergeRecord(record, currentNode)
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
        mergeRecord(currentNode, depth[0])
        break
      default:
        throw new Error('gpg record parse error')
    }
  }

  return output
}

exports.parseColons = (input, schema=DefaultSchema)=>{

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

  //debug('input ->', input)

  //debug('rows',rows)

  return exports.groupRecords(rows, schema)
}

exports.parseReaderColons = (input)=>{

  //debug('input \n', input)

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