![logo.png](README/logo.png)
# FACET4 WINDOWS 10/11

  - [**Description**](#description)
  - [**Before you run!**](#before-you-run)
  - [**Liability**](#liability)
  - [**Execution**](#execution)
  - [**Interactivity**](#interactivity)
  - [**Compatibility**](#compatibility)
  - [**Known side effects**](#known-side-effects)
  - [**Known issues**](#known-issues)
  - [**Undo changes**](#undo-changes)
  - [**Finally**](#finally)
  - [**Thanks To**](#thanks-to)


## **Description**


Firstly, this PowerShell script is designed to automate routine tasks on Windows 10 and 11 distributions, focusing on improving performance for computers and notebooks with limited CPU and RAM resources.While it is not intended to be an ``"anti-tracking"`` script or targeted at IT administrators, it aims to balance retaining desired functionality and optimising system performance.

Unlike the multitude of available ``"debloatware"`` scripts found on the web, this script incorporates various elements beyond removing unnecessary features, recognising that such removals contribute significantly to the overall lightweight nature of the system. It combines different approaches and best practices, exploring specific areas that the author believes warrant further exploration.

Considering the complexity and quality of the system supported by Microsoft and its collaborators, it would be audacious to attempt further optimisation without sacrificing essential operating system functionality. Therefore, the script identifies points where functionality can be offered in favour of performance gains while maintaining the system's overall characteristics and broad compatibility. The aim is not to create a barebones and featureless system through code, as the author does not believe in this strategy, nor does the script endorse suspicious distributions like ``ATLAS`` or ``TINY 11`` (while acknowledging their developers' efforts). It is essential to rely on ``official`` distributions designed to meet specific requirements for most users.

While tools like ``NTlite`` can be used to test scripts for optimisation purposes, it is crucial to approach the task with respect for the system's developers and a deep understanding of its nuances. Disabling features or altering kernel behaviour without comprehensive knowledge can lead to adverse effects. Filtering through official documentation, addressing misconceptions, and separating signal from noise can be time-consuming and challenging. Eventually, conclusions are drawn regarding which functions are helpful for the project, which are obsolete, which are purely cosmetic and unrelated to the project scope, and which parts can potentially impact the system. The latter three categories often represent a significant amount of noise on the web.

Based on the author's experience, optimising Windows Services extensively proved to be a fruitless endeavour. The conclusion is that it is better to accept the system as is and find contentment or specialise in low-level programming languages and kernel customisation for those seeking further customisation.


## **Before you run!**

```
☝ Although the author has made an effort to provide broad compatibility,
    this script was conceived aiming at a clean install of Windows,
    and if you use it outside that context, some programs may stop working.
    Be aware of the risk.
```

```
🚫 Do not run this script if you are not familiar with the topic.
    Some functions may reduce security, uninstall or prevent applications from running again and disable
    some internal operating system functionalities. If you don't understand what a function does, don't run it.
```

```
🚫 Never run scripts from strangers without checking the code first!
```

```
🚫 This script can damage your operating system by forcing a complete reinstallation.
    It is at your discretion and risk.
```


## **Liability**

This script has taken dozens of hours and years of experimentation on my part, self-learning, and is being shared freely for use, distribution, and study. I'm not responsible for anything. All script is provided as it is, and you can use it at your own risk.


## **Execution**

The script is divided into a module with all the functions and a preset file containing only the call of the procedures to be executed. Directly running the script.cmd file solves all these complexities for you, such as elevating privileges.

If you just want to run the script with the default preset, `download and unpack it` and then simply double-click on the script.cmd file and confirm the User Account Control prompt.

![todownload.png](README/todownload.png)


## **Interactivity**

This script is designed to run without any user interaction. Modify it as you like.

### Presets

The preset file is a simple list of function names which should be called. Any function which is not present or commented in a preset will not be called. Thus the corresponding function will not be applied.

The function name can be prefixed with an exclamation mark `!`, which will instead cause the function to be removed from the selection. This is useful when you want to apply the whole preset but omit a few specific functions in the current run.

### Log

The script automatically stores the output of the script execution in a folder like `C:\Temp\facet4` .

### System Restore Point

The script automatically tries to create a system restore point before the functions run.

System Restore is a feature designed to create a snapshot of the current working state and save it as a "restore point" when essential changes are detected on your computer. Suppose a critical issue occurs after installing an update, driver, or application or incorrectly modifying system settings in the registry, you can use a restore point to revert your laptop or desktop computer to an earlier state to resolve the issue without losing your files.


## **Compatibility**

The script was developed and tested using the latest Windows 10 and 11 Home and Pro distributions in English and Portuguese languages and aims to be fully compatible with the most up-to-date version of them, you can run the script on other distributions, but the code is still designed primarily for Home/Pro and is not compatible with versions before Windows 10.

- [x]  Windows 10 (English/Portuguese)
    - [x]  Home
    - [x]  Pro
- [x]  Windows 11 (English/Portuguese)
    - [x]  Home
    - [x]  Pro


## **Known side effects**

- Some Windows settings will show the message `Some of these settings are hidden or managed by your organization.` This is due to some functions of the script that use Group Policy Objects (GPO).
The exact mechanism is used in companies so that users without administrative privileges cannot change the settings. I'm using this because, in theory, it prevents future system updates from reverting these settings without notice. 
If you would like to make these settings available, disable the `DisableAppCompat` function in the present file before running it.
- The script disables support for legacy 16-bit applications. 
If you still use any apps from the Jurassic period, disable the `DisableAppCompat` function in the present file before running it.
- The script disables some functionality of the `Xbox` subsystem. 
If you use any games from your Xbox account, disable the `RemoveXboxFeatures` function in the present file before running.
- This script automatically changes the `Processor performance boost mode` plan according to the processor brand (AMD/Intel) and computer type (Notebook/Desktop). 

You can easily change this option by accessing the steps below:
1. Open Command Prompt: `hold down the Windows Key, and Press R` on your keyboard.
2. Type `power` in the window and press Enter.
3. Click on the `Change advanced power settings` option and scroll down to the `Processor power management` tab. The default state is `Aggressive` .
4. Follow the on-screen options to change and click on the `Apply` button. It is not necessary to restart the device.
        
![power.png](README/power.png)
        

## **Known issues**

When trying to change a specific key when using an Azure Active Directory account.

The problem is easily worked around by performing this modification manually using Regedit.


## **Undo changes**

### Reverse the entire script

Based on my "limited" knowledge acquired over the years as a user, I do not believe that reversing function by function will bring your operating system to the previous state with the same behaviour in all its details. 
I have always witnessed several inconsistencies using this approach in addition to spending many hours trying to solve this.

Based on the above, I find it advisable (which is why this built-in tool exists in Windows) to perform a **System Restore Point** before executing this script.

To revert the entire script, follow these steps:

1. Open Command Prompt `hold down the Windows Key, and Press R` on your keyboard.
2. Type `rstrui.exe` in the window, and then press Enter.
3. Find a restore point with a name like `System Restore Point dated 00/00/0000 00:00:00 before running facet4 script`. It should be the newest restore point there.
4. Follow the on-screen instructions to complete the system restore.

### Revert functions

If you want to revert some specific function, create and add this opposite (or equivalent) name function that reverts the required behaviour to the default and append it to the present file.


## **Finally**
If you understand what you are doing, consider downloading and running Microsoft Autoruns to check your system.

This utility, which has the most comprehensive knowledge of auto-starting locations of any startup monitor, shows you what programs are configured to run during system bootup or login, and when you start various built-in Windows applications like Internet Explorer, Explorer and media players. These programs and drivers include ones in your startup folder, Run, RunOnce, and other Registry keys. Autoruns reports Explorer shell extensions, toolbars, browser helper objects, Winlogon notifications, auto-start services, and much more. Autoruns goes way beyond other autostart utilities.

https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns

![autoruns_v13.png](README/autoruns_v13.png)


## **Thanks To**

The thousands of people who actively contribute to forums, websites and communities, making their knowledge available; without this, it would not be possible to waste/spend dozens of hours trying to learn things like this. 

I leave my thanks.
