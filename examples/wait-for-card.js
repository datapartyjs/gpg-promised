const SmartCardDetector = require('../src/utils/smart-card-detector')

function logEvent(type, device){
    console.log(type+' smart card found bus=', device.busNumber,
    ' address=', device.deviceAddress,
    ' vendor=', device.deviceDescriptor.idVendor,
    ' product=', device.deviceDescriptor.idProduct)
}

async function main(){

    let detector = new SmartCardDetector()

    detector.on('existing', (device)=>{
        logEvent('existing', device)
    })

    detector.on('attached', (device)=>{
        logEvent('attached', device)
    })

    detector.on('detached', (device)=>{
        logEvent('detached', device)
    })

    await detector.start()

    

}


main().then(console.log).catch(err=>{
    console.log('caught error')
    console.log(err)

    if(!err || !err.stdout || !err.stderr){ return }

    console.log('stdout [',err.stdout.toString(), ']')
    console.log('stderr [', err.stderr.toString(), ']')
})

