const os = require('os')
const GpgPromised = require('../src/index')
const KeyChain = GpgPromised.KeyChain

/***
 * 
 * This examples demostrates:
 *  - constructing a re-usable bobChain()
 *  - generating key
 * 
 */


async function main(){
  
  const bobChain = new KeyChain( )

  await bobChain.open()
  
  await bobChain.generateKey({
    email: 'bob@test.xyz',
    name: 'Bob bob',
    unattend: true,
  })

  const who = await bobChain.whoami()
  console.log('bob whoami',who)

  const bobPub = await bobChain.exportPublicKey(who[0])
  console.log(bobPub)

  const aliceChain = new KeyChain()

  await aliceChain.open()

  await aliceChain.generateKey({
    email: 'alice@test.xyz',
    name: 'Alice alice',
    unattend: true,
  })

  const imported = await aliceChain.importKey(bobPub)
  console.log('imported', imported)

  await aliceChain.trustKey(imported[0], '3')
  await aliceChain.signKey(imported[0])

  const secrets = await aliceChain.listSecretKeys(false)
  console.log('secrets', secrets)

  const other = await aliceChain.whoami()
  console.log('alice whoami',other)

  const alicePub = await aliceChain.exportPublicKey(other[0])

  const bobImported = await bobChain.importKey(alicePub)

  await bobChain.trustKey(bobImported[0], '3')
  await bobChain.signKey(bobImported[0])



  let toEmails = ['alice@test.xyz']


  const enc = await bobChain.encrypt('hello world', who.concat(toEmails), who[0])
  console.log('encrypt -', enc)

  const dec = await aliceChain.decrypt(enc, {from: 'bob@test.xyz'})
  console.log('decrypt -', dec)

  return
}



// Run main
main().catch((error) => {
  console.log(error)
  console.error(error.message)
  process.exit()
})

