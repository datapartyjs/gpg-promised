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
  
  const alice = new KeyChain( )
  await alice.open()
  await alice.generateKey({
    email: 'alice@test.xyz',
    name: 'Alice Alice',
    unattend: true,
    expire: 'seconds=5'
  })
  const aliceWho = await alice.whoami()
  const aliceId = (await alice.listSecretKeys())[0].keyid

  console.log('aliceId', aliceId)

  const bob = new KeyChain( )
  await bob.open()
  await bob.generateKey({
    email: 'bob@test.xyz',
    name: 'Bob Bob',
    unattend: true
  })
  const bobWho = await bob.whoami()
  const bobId = (await bob.listSecretKeys())[0].keyid

  
  const aliceKey = await alice.exportPublicKey(aliceWho[0])
  const bobKey = await bob.exportPublicKey(bobWho[0])
  
  

  const [bobImport] = await alice.importKey(bobKey)
  
  await alice.trustKey(bobImport, '3')
  console.log('>> alice signing bob', bobImport, bobId)
  await alice.signKey(bobImport, aliceWho[0])

  
  const [aliceImport] = await bob.importKey(aliceKey)
  
  await bob.trustKey(aliceImport, '3')
  console.log('>> bob signing alice', aliceImport)
  await bob.signKey(aliceImport, bobId)


  let toEmails = [
    bobWho[0]
  ]

  const enc = await alice.encrypt('hello world', aliceWho.concat(toEmails), aliceWho[0])
  console.log('encrypt -', enc)

  setTimeout(async()=>{

    //Expected to fail due to expired key

    const dec = await bob.decrypt(enc)
    console.log('decrypt -', dec)

    console.log('aliceId', aliceId)
    console.log('bobId', bobId)

  }, 15000)
  
  setTimeout(async()=>{

    //Expected to complain but succeed due to allowing expired & untrusted signer

    const dec2 = await bob.decrypt(enc, {
      level: {none: true},
      allow: {allow_expired_key: true}
    })
    console.log('decrypt2 -', dec2)
  }, 20000)
}



// Run main
main().catch((error) => {
  console.log(error)
  console.error(error.message)
  process.exit()
})

