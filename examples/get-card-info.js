const os = require('os')
const GPG = require('../src')


async function main(){

  //! Use a temporary keychain
  let keychain = new GPG.KeyChain()
  await keychain.open()

  try{
  
    //! check to see if card is available
    let hasCard = await keychain.hasCard()
  
    console.log('hasCard =', hasCard)
  
    if(!hasCard){
      throw new Error('smart card not detected')
    }
  
    
    //! Dump full card metadata
    let status = await keychain.cardStatus()
    console.log(status)
  }
  
  catch(err){
    console.log('error -', err.message)
  }
  
  await keychain.close()
  
  
  return 'done'

}



main().then(console.log).catch(err=>{
        console.log('caught error')
        console.log(err)

        if(!err || !err.stdout || !err.stderr){ return }

        console.log('stdout [',err.stdout.toString(), ']')
        console.log('stderr [', err.stderr.toString(), ']')
})

