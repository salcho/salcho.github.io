---
layout: post
title: "The USB protocol & HID descriptors"
date: 2024-07-05 13:37:00
---

After 2+ years of pandemic, chip shortage, economic warfare and supply chain disruptions, I've finally received my [Cynthion](https://greatscottgadgets.com/cynthion/) device. 

## Documentation & Spec reading

The USB 2.0 spec has some useful starters to understand the hierarchical structure of USB. In particular, look out for:

- Chapter 4: Architectural Overview explains USB host & devices and how they relate to each other.
- Data Flow Types: Uni-directional or bi-directional pipes. Control, Bulk, Interrupt and Isochronous data transfers.

The [Device Class Definition for Human Interface Devices (HID)](https://usb.org/sites/default/files/hid1_11.pdf) spec describes the interfaces and descriptors that HID devices need to present to USB hosts. Look out for:

- Chapter 3: Management Overview. Very boring name, has great diagrams showing the relationship between USB descriptors (device/config/interface) and HID descriptors.
- Chapter 5.2: Report Descriptors.

[USB in a Nutshell](https://www.beyondlogic.org/usbnutshell/usb1.shtml) by Craig Peacock is an amazing resource.

## Find the device descriptor for a connected device

```bash
lsusb
lsusb -s 003:020 -vvvv
```

## Find the report descriptor of a HID device

For whatever reason, lsof refuses to provide report descriptor for some (all?) HID devices. To work around this, I've used [usbhid-dump](https://github.com/DIGImend/usbhid-dump) in combination with [hidrd-convert](https://github.com/DIGImend/hidrd), which pretty prints the raw binary descriptor.

```bash
sudo usbhid-dump | grep -v : | xxd -r -p | hidrd-convert -o spec
```

## MITM USB traffic

Upload the analyzer bitstream to the FPGA. This will allow [Packetry](https://github.com/greatscottgadgets/packetry) to sniff USB traffic and produce pcap files.

```bash
cynthion run analyzer
cd packetry/ && cargo run
```

## Emulate USB devices

Upload the facedancer bitstream to emulate any a USB device. 

```bash
cynthion run facedancer
python legit_mouse.py
```

The [Facedancer API](https://github.com/greatscottgadgets/facedancer) has a great declarative interface to emulate devices. 

There is a [spec detail](https://www.beyondlogic.org/usbnutshell/usb4.shtml#:~:text=The%20endpoint%20number%20should%20be%20zero%2C%20specifying%20the%20default%20pipe.) in explained in the Control Transfers section, where the spec *reserves endpoint number 0* as the default pipe. Because of this, emulated devices need to start with endpoint numbers > 0.

This script emulates a simple HID mouse:


```python

#!/usr/bin/env python3

import logging
import random

import usb1

from facedancer import main
from facedancer import *
from facedancer.classes import USBDeviceClass
from facedancer.classes.hid.descriptor import (
    COLLECTION,
    END_COLLECTION,
    INPUT,
    LOGICAL_MAXIMUM,
    LOGICAL_MINIMUM,
    REPORT_COUNT,
    REPORT_SIZE,
    USAGE,
    USAGE_MAXIMUM,
    USAGE_MINIMUM,
    USAGE_PAGE,
    HIDCollection,
    HIDReportDescriptor,
)
from facedancer.classes.hid.usage import HIDGenericDesktopUsage, HIDUsagePage
from pygreat.errors import DeviceNotFoundError


@use_inner_classes_automatically
class LegitMouseDevice(USBDevice):
    name: str = "Legit USB mouse device"
    max_packet_size_ep0: int = 8
    vendor_id: int = 0x1209
    product_id: int = 0xC007
    manufacturer_string: str = "Sal Industries"
    product_string: str = "Legit USB Device"
    serial_number_string: str = "541"
    supported_languages: tuple = (LanguageIDs.ENGLISH_US,)
    device_revision: int = 0x72
    usb_spec_version: int = 0x0002
    device_class: int = 0
    device_subclass: int = 0
    protocol_revision_number: int = 0
    class LegitMouseConfiguration(USBConfiguration):
        max_power: int = 100
        self_powered: bool = False
        class LegitMouseInterface(USBInterface):
            name: str = "Legit mouse interface"
            class_number: int = USBDeviceClass.HID
            subclass_number: int = 1
            protocol_number: int = 2
            # HID Device Descriptor:
            # bLength                 9
            # bDescriptorType        33
            # bcdHID               1.11
            # bCountryCode            0 Not supported
            # bNumDescriptors         1
            # bDescriptorType        34 Report
            # wDescriptorLength      46
            class LegitClassDescriptor(USBClassDescriptor):
                number: int = USBDescriptorTypeNumber.HID
                raw: bytes = b"\x09\x21\x11\x01\x00\x01\x22\x2e\x00"

            class ReportDescriptor(HIDReportDescriptor):
                fields: tuple = (
                    USAGE_PAGE(HIDUsagePage.GENERIC_DESKTOP),
                    USAGE(HIDGenericDesktopUsage.MOUSE),
                    COLLECTION(HIDCollection.APPLICATION),
                    USAGE(HIDGenericDesktopUsage.POINTER),
                    COLLECTION(HIDCollection.PHYSICAL),
                    USAGE_PAGE(HIDUsagePage.BUTTONS),
                    USAGE_MINIMUM(0x1),
                    USAGE_MAXIMUM(0x3),
                    LOGICAL_MINIMUM(0),
                    LOGICAL_MAXIMUM(1),
                    REPORT_COUNT(8),
                    REPORT_SIZE(1),
                    INPUT(variable=True),
                    USAGE_PAGE(HIDUsagePage.GENERIC_DESKTOP),
                    USAGE(HIDGenericDesktopUsage.X),
                    USAGE(HIDGenericDesktopUsage.Y),
                    USAGE(HIDGenericDesktopUsage.WHEEL),
                    # LOGICAL_MINIMUM(-127), Facedancer has a bug where it fails to encode negative numbers in report descriptors
                    LOGICAL_MINIMUM(0),
                    LOGICAL_MAXIMUM(127),
                    REPORT_SIZE(8),
                    REPORT_COUNT(3),
                    INPUT(variable=True, relative=True),
                    END_COLLECTION(),
                    END_COLLECTION(),
                    # We're skipping the mouse wheel
                    # INPUT(),
                    # USAGE_PAGE(HIDUsagePage.GENERIC_DESKTOP),
                    # USAGE_ HIDUsage.X,
                    # HIDUsage.Y,
                    # HIDUsage.WHEEL,
                    # HIDLogicalMinimum(-127),
                    # HIDLogicalMaximum(127),
                    # HIDReportSize(8),
                    # HIDReportCount(3),
                    # HIDInputVariableRelative,
                )

            class LegitMouseInEndpoint(USBEndpoint):
                number: int = 3
                direction: USBDirection = USBDirection.IN
                transfer_type: USBTransferType = USBTransferType.INTERRUPT
                max_packet_size: int = 0x40
                interval: int = 10

    # Send a left or right mouse click at random
    def handle_data_requested(self, endpoint: USBEndpoint):
        if random.random() < 0.3:
            # Randomly select between left and right click
            click = 1 if random.random() < 0.5 else 2
            logging.info(f"Sending mouse click: {click}")
            endpoint.send(bytes([click, 0, 0, 0]))
        else:
            endpoint.send(bytes([0, 0, 0, 0]))

try:
    main(LegitMouseDevice)
except DeviceNotFoundError as e:
    logging.error(
        f"Device not found - is the facedancer bitstream loaded? Take control back from PROG"
    )
except usb1.USBErrorTimeout as e:
    logging.error(f"USB timeout ({e}) - try running rubber-ducky.py first")
```

