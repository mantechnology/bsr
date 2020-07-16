' ***************************************************************************
' Copyright(c)2007-2015 ManTechnology Co., LTD. All rights reserved.
' ***************************************************************************
strComputer = "." 
Set objWMIService = GetObject("winmgmts:" _ 
    & "{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2") 
 
Set colItems = objWMIService.ExecQuery("Select * from Win32_PnPEntity")

Wscript.Echo "Class Guid,Description,Device ID,Manufacturer,Name,PNP Device ID,Service"
For Each objItem in colItems 
    Wscript.Echo """" & objItem.ClassGuid & """,""" & objItem.Description & """,""" & objItem.DeviceID & """,""" & objItem.Manufacturer & """,""" & objItem.Name & """,""" & objItem.PNPDeviceID &  """,""" & objItem.Service & """"
Next 

