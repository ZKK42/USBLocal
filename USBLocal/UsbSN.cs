using System;
using System.Management;

namespace USBLocal
{
    class UsbSN
    {
        public bool Usbserinokontrol()
        {
            bool kontrol = false;
            string serino = "4C530499930219119355";
            ManagementObjectSearcher usb = new ManagementObjectSearcher("Select * from Win32_DiskDrive where InterfaceType='USB'");
            foreach (var usbveri in usb.Get())
            {
                if (usbveri["SerialNumber"].ToString() == serino)
                    kontrol = true;
                Console.WriteLine("USB SERİ NO :"+usbveri["SerialNumber"].ToString());
            }
            return kontrol=true;
        }
    }
}
