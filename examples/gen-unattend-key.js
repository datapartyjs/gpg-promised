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
  
  const keychain = new KeyChain( )

  await keychain.open()
  
    //! Make a connected security card the primary identity
    //await keychain.trustCard()


  await keychain.generateKey({
    email: 'bob@test.xyz',
    name: 'Bob bob',
    unattend: true,
  })

  const who = await keychain.whoami()
  console.log('whoami',who)

  const key = await keychain.exportSecretKey(who[0])
  console.log(key)

  const otherChain = new KeyChain()

  await otherChain.open()

  await otherChain.generateKey({
    email: 'alice@test.xyz',
    name: 'Alice alice',
    unattend: true,
  })

  const imported = await otherChain.importKey(key)
  console.log('imported', imported)

  await otherChain.trustKey(imported[0], '6')

  const secrets = await otherChain.listSecretKeys(false)
  console.log('secrets', secrets)

  const other = await otherChain.whoami()
  console.log('other whoami',other)



  let toEmails = []


  const enc = await keychain.encrypt('hello world', who.concat(toEmails), who[0])
  console.log('encrypt -', enc)

  const dec = await keychain.decrypt(enc)
  console.log('decrypt -', dec)

  return
}



// Run main
main().catch((error) => {
  console.log(error)
  console.error(error.message)
  process.exit()
})

