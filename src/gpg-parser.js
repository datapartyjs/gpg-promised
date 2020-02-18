const Hoek = require('@hapi/hoek')
const HoekTransform = require('transform-hoek').transform
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

const SIG_PARSER = (obj)=>{
  return {
    'keyid_or_fpr': obj.args[0],
    username: obj.args.slice(1).join(' ')
  }
}

const CRYPTO_INFO_TRANSFORM = {
  mdc_method: 'args.0',
  sym_algo: 'args.1',
  aead_algo: 'args.2'
}


const STATUS_TRANSFORMS = {
  NEWSIG: { signers_uid: 'args' },
  GOODSIG: SIG_PARSER,
  EXPSIG: SIG_PARSER,
  EXPKEYSIG: SIG_PARSER,
  REVKEYSIG: SIG_PARSER,
  BADSIG: SIG_PARSER,
  ERRSIG: {
    keyid: 'args.0',
    pkalgo: 'args.1',
    hashalgo: 'args.2',
    sig_class: 'args.3',
    time: 'args.4',
    rc: 'args.5',
    fpr: 'args.6',
  },
  VALIDSIG: {
    fingerprint: 'args.0',
    sig_creation_date: 'args.1',
    sig_timestamp: 'args.2',
    expire_timestamp: 'args.3',
    sig_version: 'args.4',
    reserved: 'args.5',
    public_key_algo: 'args.6',
    hash_algo: 'args.7',
    sig_class: 'args.8',
    primary_key_fpr: 'args.9'
  },
  SIG_ID: {
    radix: 'args.0',
    sig_creation_date: 'args.1',
    sig_timestamp: 'args.2'
  },
  ENC_TO: {
    keyid: 'args.0',
    keytype: 'args.1',
    keylength: 'args.2'
  },
  BEGIN_DECRYPTION: {},
  END_DECRYPTION: {},
  DECRYPTION_KEY: {
    fpr: 'args.0',
    fpr2: 'args.1',
    otrust: 'args.2'
  },
  DECRYPTION_INFO: CRYPTO_INFO_TRANSFORM,
  DECRYPTION_FAILED: {},
  DECRYPTION_OKAY: {},
  SESSION_KEY: (obj)=>{
    const [algo, hexdigits] = Hoek.reach(obj, 'args.0', {default:[]}).split(':')

    return { algo, hexdigits }
  },
  BEGIN_ENCRYPTION: CRYPTO_INFO_TRANSFORM,
  END_ENCRYPTION: {},
  BEGIN_SIGNING: {},
  ALREADY_SIGNED: { keyid: 'args.0' },
  SIG_CREATED: {
    type: 'args.0',
    pk_algo: 'args.1',
    hash_algo: 'args.2',
    class: 'args.3',
    timestamp: 'args.4',
    keyfpr: 'args.5'
  },
  PLAINTEXT: {
    format: 'args.0',
    timestamp: 'args.1',
    filename: 'args.2'
  },
  PLAINTEXT_LENGTH: {length: 'args.0'},
  ENCRYPTION_COMPLIANCE_MODE: {flags: 'args'},
  DECRYPTION_COMPLIANCE_MODE: {flags: 'args'},
  VERIFICATION_COMPLIANCE_MODE: {flags: 'args'},
  KEY_CONSIDERED: {
    fpr: 'args.0',
    flags: 'args.1'
  },
  KEYEXPIRED: {timestamp: 'args.0'},
  KEYREVOKED: {},
  NO_PUBKEY: {},
  NO_SECKEY: {keyid: 'args.0'},
  KEY_CREATED: {
    type: 'args.0',
    fingerprint: 'args.1',
    handle: 'args.2'
  },
  KEY_NOT_CREATED: {handle: 'args.0'},
  TRUST_UNDEFINED: { error: 'args' },
  TRUST_NEVER: { error: 'args' },
  TRUST_MARGINAL: { code: 'args.0', validation_model: 'args.1' },
  TRUST_FULLY: { code: 'args.0', validation_model: 'args.1' },
  TRUST_ULTIMATE: { code: 'args.0', validation_model: 'args.1' },
  GOODMDC: {},
  FAILURE: {
    location: 'args.0',
    code: 'args.1'
  },
  SUCCESS: {
    location: 'args.0',
  },
  WARNING: (obj)=>{
    return {
      location: obj.args[0],
      code: obj.args[1],
      text: obj.args.slice(2).join(' ')
    }
  },
  ERROR: (obj)=>{
    return {
      location: obj.args[0],
      code: obj.args[1],
      mode: obj.args.slice(2)
    }
  },
  CARDCTRL: {
    what: 'args.0',
    serialno: 'args.1'
  },
  SC_OP_FAILURE: {
    code: 'args.0'
  },
  SC_OP_SUCCESS: {},
  INV_RECP: {
    reason: 'args.0',
    recipient: 'args.1'
  },
  INV_SGNR: {
    reason: 'args.0',
    sender: 'args.1'
  }
}

exports.parseStatusFd = (input)=>{
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