

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
  },
  IMPORTED: SIG_PARSER,
  IMPORT_OK: {
    reason: 'args.0',
    fingerprint:'args.1'
  },
  IMPORT_PROBLEM: {
    reason: 'args.0',
    fingerprint:'args.1'
  },
  IMPORT_RES: {
    count: 'args.0',
    no_user_id: 'args.1',
    imported: 'args.2',
    reserved: 'args.3',
    unchanged: 'args.4',
    n_uids: 'args.5',
    n_subk: 'args.6',
    n_sigs: 'args.7',
    n_revoc: 'args.8',
    sec_read:'args.9',
    sec_imported:'args.10',
    sec_dups:'args.11',
    skipped_new_keys:'args.12',
    not_imported: 'args.13',
    skipped_v3_keys:'args.14'
  },
  EXPORTED: {fingerprint: 'args.0'},
  EXPORT_RES: {
    count: 'args.0',
    secret_count: 'args.1',
    exported: 'args.2'
  }
}


module.exports = STATUS_TRANSFORMS