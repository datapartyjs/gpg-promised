const os = require('os')
const GpgPromised = require('../src/index')
const KeyChain = GpgPromised.KeyChain


/***
 * 
 * This examples demostrates:
 *  - constructing a temporary KeyChain()
 *  - rooting trust in an inserted security card
 *  - recieving keys
 *  - encrypting content
 *  - decrypting content
 * 
 */


async function main(){
  const toEmails = process.argv.slice(2)

  if(toEmails.length < 1){
    console.log('No to user emails provided!\n\n')
    console.log('Usage: '+process.argv.slice(0,2)+ ' <email> ...')
    process.exit()
  }
  
  //! Construct a temporary gpg keychain
  const keychain = new KeyChain()

  //! open keychain for operations
  await keychain.open()

  //! Make a connected security card the primary identity
  await keychain.trustCard()

  //! Download keys for reciepents
  for(const toEmail of toEmails){
    console.log('recvKey -', toEmail)
    const toKeyLookup = await keychain.lookupKey(toEmail)
    await keychain.recvKey(toKeyLookup.keyid)
  }
  
  const who = await keychain.whoami()
  console.log('whoami',who)

  const enc = await keychain.encrypt('hello world', who.concat(toEmails), who[0])
  console.log('encrypt -', enc)

  const dec = await keychain.decrypt(enc)
  console.log('decrypt -', dec)
}



// Run main
main().catch((error) => {
  console.log(error)
  console.error(error.message)
  process.exit()
})

