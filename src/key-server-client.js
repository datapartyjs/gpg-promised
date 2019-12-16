



const Url = require('url').URL
const debug = require('debug')('gpg.KeyServerClient')
const request = require('request-promise')

const GPGParser = require('./gpg-parser')

/**
 * Schema for parsing search index from csv to json
 * @typedef {Object} HKPIndexSchema
 * @property {object} types
 * @property {object} types.info  info schame
 * @property {object} types.pub   pub schema
 * @property {object} types.uid   uid schema
 */
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

  /**
   
  */

  /**
   * A client for PGP HKP Servers (Http Keyserver Protocol), see {@link https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00|IETF spec} for protocol information.
   * @class
   * @constructor
   * @param {string} url Address of server, defaults to `KeyServerClient.Addresses.ubuntu`
   */
  constructor(url){
    /**
     * @type {Url}
     */
    this.baseUri = new Url( url || KeyServerClient.Addresses.ubuntu )
  }

  /**
   * Search for keys using text
   * @method
   * @param {string} text Search text
   * @returns {string} parsed colon-seperated-values into json
   */
  async search(text, exact=false){
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

  /**
   * @todo Not implemented
   * @method
   * @param {string} keyid 
   */
  async fetch(keyid){
    /** todo */
    throw new Error('not implemented')
  }

  /**
   * @type {Object}
   * @property {string} ubuntu https://keyserver.ubuntu.com
   * @property {string} gnupg http://keys.gnupg.net
   * @property {string} mit http://pgp.mit.edu
   */
  static get Addresses(){
    return {
      ubuntu: 'https://keyserver.ubuntu.com',
      gnupg: 'http://keys.gnupg.net',
      mit: 'http://pgp.mit.edu/'
    }
  }
}

module.exports = KeyServerClient