
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