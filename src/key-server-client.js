
/**
 * On Http Keyserver Protocol (HKP)
 * https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob;f=doc/KEYSERVER;h=f63200a6b464282f4acda19ac4ef615e375d517f;hb=HEAD
 * https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00#section-3.1
 */


const Url = require('url').URL
const debug = require('debug')('gpg.KeyServerClient')
const request = require('request-promise')

const GPGParser = require('./gpg-parser')

const HKPIndexSchema = {
  types: {
    info: {
      depth: 1,
      fields: {
        1: 'type',
        2: 'version',
        3: 'count'
      }
    },
    pub: {
      depth: 1,
      fields: {
        1: 'type',
        2: 'keyid',
        3: 'algo',
        4: 'keylen',
        5: 'creationdate',
        6: 'expirationdate',
        7: 'flags'
      }
    },
    uid: {
      depth: 2,
      fields: {
        1: 'type',
        2: 'user_id',
        3: 'creationdate',
        4: 'expirationdate',
        5: 'flags'
      }
    }
  }
}

class KeyServerClient {
  constructor(uri){
    this.baseUri = new Url( uri || KeyServerClient.Address.ubuntu )
  }

  async search(text){
    const searchUrl = new Url ('/pks/lookup', this.baseUri)

    searchUrl.searchParams.append('op', 'vindex')
    searchUrl.searchParams.append('options', 'mr')
    searchUrl.searchParams.append('search', text)
    //searchUrl.searchParams.append('fingerprint', 'on')


    debug('searching', searchUrl.toString())

    let index = {}
    
    const result = await request( searchUrl.toString() )
    
    debug('result', result)

  
    const parsed = GPGParser.parseColons(result, HKPIndexSchema)

    debug('parsed', parsed)

    return parsed
    
  }

  async fetch(keyid){
    //
  }

  static get Address(){
    return {
      ubuntu: 'https://keyserver.ubuntu.com',
      gnupg: 'http://keys.gnupg.net',
      mit: 'http://pgp.mit.edu/'
    }
  }
}

module.exports = KeyServerClient