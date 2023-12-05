const usb = require('usb')
const debug = require('debug')('SmartCardDetector')
const EventEmitter = require('events').EventEmitter

class SmartCardDetector extends EventEmitter {

    constructor(){
        super()
    }

    handleDeviceEvent(type, device){
        let isSmartCard = SmartCardDetector.hasCCID(device)
    
        if(isSmartCard){
            debug(type+' smart card found bus=', device.busNumber,
                        ' address=', device.deviceAddress,
                        ' vendor=', device.deviceDescriptor.idVendor,
                        ' product=', device.deviceDescriptor.idProduct)

            this.emit(type, device)
        }
    }

    async start(){
        const devices = usb.getDeviceList()

        //debug('attached', devices)
    
        for(let device of devices){
            this.handleDeviceEvent('existing',device)
        }
    
        usb.usb.on('attach', (device)=>{
            this.handleDeviceEvent('attached', device)
        }) 
    
    
        usb.usb.on('detach', (device)=>{
            this.handleDeviceEvent('detached', device)
        })
    }

    static hasCCID(device){
        let foundCCID = device.deviceDescriptor.bDeviceClass == 0xB

        for(let config of device.allConfigDescriptors){

            for(let ifaceArr of config.interfaces){
                let iface = ifaceArr[0]

                if(iface.bInterfaceClass == 0xB){
                    foundCCID=true
                    break
                }
            }
        }

        return foundCCID
    }
}


module.exports = SmartCardDetector