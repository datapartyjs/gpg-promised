# gpg-promised

`The GPG interface for nodejs we were promised`

 * Examples - [examples/](https://github.com/datapartyjs/gpg-promised/tree/master/examples)
 * Documentation - [datapartyjs.github.io/gpg-promised/](https://datapartyjs.github.io/gpg-promised/)
 * NPM - [npmjs.com/package/gpg-promised](https://www.npmjs.com/package/gpg-promised)
 * Code - [github.com/datapartyjs/gpg-promised](https://github.com/datapartyjs/gpg-promised)
 * Social - [@datapartyjs](https://twitter.com/datapartyjs)

 ```js
  const GpgPromised = require('gpg-promised')
  const KeyChain = GpgPromised.KeyChain

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
 ```
