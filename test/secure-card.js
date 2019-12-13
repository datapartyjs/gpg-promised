const os = require('os')
const GpgPromised = require('../src/index')
const KeyChain = GpgPromised.KeyChain



async function main(){
  
  const keychain = new KeyChain( os.homedir() + '/.gpg-promised')

  await keychain.open()

  await keychain.trustCard()

  const toEmail = 'dpctest+bob@roshub.io'
  const toKeyLookup = await keychain.lookupKey(toEmail)
  
  await keychain.recvKey(toKeyLookup.keyid)
  
  const who = await keychain.whoami()
  console.log('whoami',who)

  const enc = await keychain.encrypt('hello world', who.concat([toEmail]), who[0])
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

