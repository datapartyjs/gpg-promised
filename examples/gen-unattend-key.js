const os = require('os')
const GpgPromised = require('../src/index')
const KeyChain = GpgPromised.KeyChain

/***
 * 
 * This examples demostrates:
 *  - constructing a re-usable KeyChain()
 *  - generating key
 * 
 */


async function main(){
  
  const keychain = new KeyChain( os.homedir() + '/.gpg-promised')

  await keychain.open()
  
  await keychain.generateKey({
    email: 'test@test.xyz',
    name: 'Bob bob',
    unattend: true,
  })

  const who = await keychain.whoami()
  console.log('whoami',who)

  return
}



// Run main
main().catch((error) => {
  console.log(error)
  console.error(error.message)
  process.exit()
})

