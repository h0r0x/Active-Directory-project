# Active Directory Project

Status: In progress
Assign: Gabriele T4m

# Introduction

In the ever-evolving landscape of cybersecurity, understanding how to secure and manage networks efficiently is essential. Active Directory (AD), a cornerstone of enterprise network management, is widely used to control and maintain resources like users, computers, and groups. This project provides a comprehensive, hands-on guide to building a fully functional AD environment within a home lab setup. By replicating a professional security operation center (SOC), learners can experiment, analyze, and refine their skills in both offensive and defensive security.

CREDITS:  [https://www.youtube.com/watch?v=5OessbOgyEo&pp=ygUnYWN0aXZlIGRpcmVjdG9yeSBjeWJlciBzZWN1cml0eSBwcm9qZWN0](https://www.youtube.com/watch?v=5OessbOgyEo&pp=ygUnYWN0aXZlIGRpcmVjdG9yeSBjeWJlciBzZWN1cml0eSBwcm9qZWN0).

CREDITS: [https://www.youtube.com/watch?v=xftEuVQ7kY0](https://www.youtube.com/watch?v=xftEuVQ7kY0)

### **Objectives**

- **Build a Secure AD Network:** Create an isolated environment to understand the structure and function of AD services.
- **Simulate Cyber Attacks:** Use Kali Linux and Atomic Red Team to launch controlled attacks, enhancing offensive cybersecurity skills.
- **Set Up Monitoring Tools:** Install and configure Splunk for comprehensive telemetry data collection and analysis.
- **Design Custom Alerts and Reports:** Learn how to build specific alerts and reports in Splunk, providing real-time insights into network activity.

### **Goals**

- **Develop Network Design Skills:** Construct a detailed network diagram to map out the relationships between servers, clients, and monitoring tools.
- **Improve AD Administration Capabilities:** Manage and configure AD services, gaining critical skills in user, computer, and group management.
- **Master Log Analysis:** Deepen your understanding of log analysis using Sysmon and Splunk Universal Forwarder for effective monitoring.
- **Strengthen Cybersecurity Posture:** Implement detection and response strategies based on telemetry data, preparing for real-world security challenges.

### **Learnings and Why**

This project bridges the gap between theoretical knowledge and practical application. By setting up an Active Directory environment from scratch, you'll understand how AD services form the backbone of network security and management. Simulating attacks using tools like Kali Linux provides insight into the tactics, techniques, and procedures (TTPs) employed by threat actors. Monitoring telemetry with Splunk deepens your analytical capabilities, allowing you to identify and understand malicious activities efficiently. In essence, this project enables learners to **hone their technical and analytical skills** while fostering **strategic thinking** to effectively secure an enterprise network

---

# **Diagram Creation and Planning**

The lab will have:

- A Splunk server (Ubuntu-based).
- An AD server (Windows Server 2022).
- A Windows 10 target machine.
- An attacker machine (Kali Linux).
- Switches, routers, and cloud/internet representation for clarity.

## **Theoretical Knowledge**

To understand the structure and purpose of each component in the Active Directory (AD) project, let's explore the theoretical roles and functions of each concept:

1. **Active Directory (AD):** A Microsoft technology used for network and identity management. AD is built on domain services that provide centralized authentication and authorization for users, groups, and devices. It employs protocols like Kerberos for secure authentication and LDAP for directory queries. AD Domain Services (AD DS) facilitate group policies, security management, and resource control.
2. **Splunk Server:** Splunk is a data analytics platform that ingests, indexes, and analyzes log data in real time. As a Security Information and Event Management (SIEM) system, it helps detect, analyze, and respond to security threats by aggregating and correlating telemetry from different network devices.
3. **Sysmon:** A Windows system monitoring tool that provides detailed information on various system events, such as process creation, network connections, and file changes. When integrated with Splunk via the Universal Forwarder, it allows real-time logging and monitoring of critical system activities.
4. **Splunk Universal Forwarder:** A lightweight version of Splunk designed to send log data from different systems to a central Splunk instance. It acts as a bridge between individual machines and the Splunk server.
5. **Atomic Red Team:** An open-source project that provides a collection of security tests simulating common attack techniques. It helps users understand how real-world adversaries operate by mimicking their tactics, techniques, and procedures (TTPs).
6. **Kali Linux:** A penetration testing distribution that offers a suite of tools to simulate cyber attacks. It allows ethical hackers to conduct reconnaissance, scanning, and exploitation of vulnerabilities to assess network defenses.
7. **Virtual Networking and Switches:** VirtualBox allows the creation of isolated virtual networks that can mimic enterprise environments. Switches facilitate communication between devices while ensuring logical separation and data flow control.

## **Diagram**

![Diagram.drawio.png](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Diagram.drawio.png)

With the theoretical framework established, the diagram illustrates the relationship between these components in a controlled lab environment:

- **Splunk Server:** An Ubuntu server (IP: 192.168.10.10) configured to receive logs from other systems. It monitors and analyzes security data, providing insights through dashboards, alerts, and reports.
- **Active Directory Server:** A Windows Server 2022 instance (IP: 192.168.10.7) promoted to a Domain Controller. It manages user authentication, group policies, and resource control.
- **Target Machine:** A Windows 10 client machine assigned a dynamic IP via DHCP. This machine acts as an endpoint that forwards telemetry data using Sysmon and Splunk Universal Forwarder. It also hosts Atomic Red Team for attack simulations.
- **Attacker:** The Kali Linux machine (IP: 192.168.10.250) simulates external threats to test the network's defensive capabilities. It employs tools like Hydra and Metasploit for brute-force and other attacks.
- **Switch and Internet:** A switch provides logical connectivity between machines, while the internet connection allows simulated external access.

The diagram visually represents the components, showing how they interconnect and facilitate data flow.

---

# **Environment Setup**

The "Environment Setup" chapter provides a thorough guide to replicating the virtual environment for the Active Directory project. Follow these detailed steps to ensure accurate replication of VirtualBox installation, VM configuration, and network setup.

## **Installing VirtualBox**

- Visit [virtualbox.org](https://virtualbox.org/) and click "Downloads" from the left-hand menu.
- Select the appropriate installer for your operating system:
    - **Windows:** Click "Windows hosts."
    - **macOS:** Click "macOS hosts."
    - **Linux:** Click "Linux distributions" and choose the version that matches your distribution.
- Once the installer downloads, follow these steps:
    - **Windows:** Double-click the **`.exe`** file to start the setup wizard, then click "Next" until "Finish."
    - **macOS:** Double-click the **`.dmg`** file, then drag the VirtualBox icon to the Applications folder.
    - **Linux:** Follow the instructions specific to your distribution to add the VirtualBox repository and install it via terminal.

## **Creating the Virtual Machines**

Now its time to create the VM that we are going to use in this project.

![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled.png)

Following the instruction for every machine.

### **Kali Linux**

<aside>
🔑 `kali/kali`

</aside>

- Download the pre-built Kali Linux VM ([https://www.kali.org/get-kali/#kali-virtual-machines](https://www.kali.org/get-kali/#kali-virtual-machines)).
- Double-click the downloaded **`.vbox`** file to import it into VirtualBox.
- Use the default credentials (**`kali`**/**`kali`**) to login.

### **Windows Server 2022**

<aside>
🔑 `Administrator/Password1234`

</aside>

- Download the Windows Server 2022 evaluation ISO from Microsoft's website ([https://info.microsoft.com/ww-landing-windows-server-2022.html?lcid=it](https://info.microsoft.com/ww-landing-windows-server-2022.html?lcid=it)).
- Open VirtualBox and click the "New" button at the top-left corner of the window.
- Enter the following details:
    - **Name:** **`WindowsServer2022`**
    - **Type:** **`Microsoft Windows`**
    - **Version:** **`Windows Server 2022 (64-bit)`**
- Click "Next."
- **Memory Size:** Set at least 4096 MB (4 GB). Click "Next."
- **Hard Disk:** Select "Create a virtual hard disk now" and click "Create."
- **Hard Disk File Type:** Choose "VDI (VirtualBox Disk Image)" and click "Next."
- **Storage on Physical Hard Disk:** Choose "Dynamically allocated" and click "Next."
- **File Location and Size:** Set the size to 50 GB and click "Create."
- Click "Settings" to open the configuration.
- In the "Storage" tab, click the empty CD icon under "Controller: IDE," then click the CD icon on the right, select "Choose a disk file," and locate the Windows Server 2022 ISO file.
- Click "OK" to apply the changes.
- Click "Start" to begin the installation. Follow the on-screen prompts to install Windows Server 2022, and set a secure administrator password.

![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%201.png)

![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%202.png)

![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%203.png)

![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%204.png)

![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%205.png)

### **Splunk Server (Ubuntu)**

- Download the Ubuntu Server ISO file.
- Click "New" in VirtualBox and enter:
    - **Name:** **`Splunk-Server`**
    - **Type:** **`Linux`**
    - **Version:** **`Ubuntu (64-bit)`**
- Click "Next."
- **Memory Size:** Set at least 8192 MB (8 GB). Click "Next."
- **Hard Disk:** Select "Create a virtual hard disk now" and click "Create."
- **Hard Disk File Type:** Choose "VDI" and click "Next."
- **Storage on Physical Hard Disk:** Choose "Dynamically allocated" and click "Next."
- **File Location and Size:** Set the size to 100 GB and click "Create."
- In "Settings," under "Storage," click the empty CD icon, then click the CD icon on the right, select "Choose a disk file," and locate the Ubuntu Server ISO file.
- Click "OK" to apply the changes.
- Click "Start" to begin installation. Follow the prompts to install Ubuntu Server.

### **Windows 10**

- Download the Windows 10 ISO using the Media Creation Tool.
- Click "New" in VirtualBox and enter:
    - **Name:** **`Windows10 - Victim AD Project`**
    - **Type:** **`Microsoft Windows`**
    - **Version:** **`Windows 10 (64-bit)`**
- Click "Next."
- **Memory Size:** Set at least 4096 MB (4 GB). Click "Next."
- **Hard Disk:** Select "Create a virtual hard disk now" and click "Create."
- **Hard Disk File Type:** Choose "VDI" and click "Next."
- **Storage on Physical Hard Disk:** Choose "Dynamically allocated" and click "Next."
- **File Location and Size:** Set the size to 50 GB and click "Create."
- Click "Settings" and navigate to the "Storage" tab.
- Click the empty CD icon, select the CD icon on the right, choose "Choose a disk file," and find the Windows 10 ISO file.
- Click "OK" to apply the changes.
- Click "Start" and follow the installation prompts to install Windows 10.

![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%206.png)

![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%207.png)

![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%208.png)

![Chose your language](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%209.png)

Chose your language

![Click “install now”](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2010.png)

Click “install now”

![Click “I don’ have a product key”](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2011.png)

Click “I don’ have a product key”

![Select “Windows 10 Pro”](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2012.png)

Select “Windows 10 Pro”

![Click on “Custom Install”](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2013.png)

Click on “Custom Install”

---

# **Network Configuration**

## **Creating a NAT Network**

A NAT (Network Address Translation) network is crucial for setting up an isolated yet internet-connected environment within VirtualBox. Here’s why we create it:

- **Isolated Lab Environment:** The NAT network creates a virtual subnet, allowing the virtual machines to communicate with one another while remaining isolated from the host and external networks. This ensures that any testing done within the lab does not affect the host machine.
- **Internet Access:** Although isolated, each virtual machine can still access the internet through the host system, which is useful for downloading necessary updates and tools.
- **Security:** By providing a separate IP range for the virtual machines, the NAT network adds a layer of security, preventing external access to internal testing environments while still enabling communication among the VMs.

To create it:

- In VirtualBox, click "File" > "Host Network Manager."
- Click "Create" to generate a new network.
- Click the pencil (edit) icon, then:
    - **Network Name:** Enter a descriptive name like **`AD-Project`**.
    - **IPv4 Address:** **`192.168.10.1/24`**
    - **DHCP Server:** Check "Enable DHCP Server".
- Click "Apply," then "Close."

![Parameters of the new NAT network.](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2014.png)

Parameters of the new NAT network.

## **Assigning Network Settings to Each VM**

Configuring each virtual machine to use the NAT network ensures that all VMs can access the isolated environment with internet connectivity.

- **Inter-VM Communication:** Assigning the network settings ensures all virtual machines are on the same subnet, making it possible for them to communicate seamlessly.
- **Simulating Real-World Networks:** This setup replicates a small-scale production network where multiple devices interact, reflecting real-world scenarios for Active Directory or attack simulation.

To do it:

- Select each VM, click "Settings," and navigate to the "Network" tab.
- In "Adapter 1," ensure "Attached to:" is set to "NAT Network."
- Choose the newly created **`AD-Project`** from the "Name" drop-down.
- Click "OK."
    
    ![Example of updated network settings of “Splunk” VM after update them.](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2015.png)
    
    Example of updated network settings of “Splunk” VM after update them.
    

## **Static IP Address Configuration**

Static IP configuration assigns specific IP addresses to essential servers like the Splunk Server and the Active Directory (AD) Domain Controller.

- **Predictable Network Structure:** Static IPs ensure that servers retain the same IP addresses across reboots, making it easier to locate and access them consistently.
- **Simplified Troubleshooting:** Knowing the exact IP address of critical services aids in troubleshooting issues quickly and accurately.
- **Active Directory Requirement:** AD Domain Controllers often require static IP addresses to ensure that clients can reliably locate them for authentication and resource management.
- **Splunk Server Connectivity:** The Splunk server requires a static IP so that other systems can forward logs and telemetry data to it without interruptions.

### **Splunk Server (Ubuntu):**

- Open a terminal and type **`sudo nano /etc/netplan/01-netcfg.yaml`** to edit the network configuration file.
- Replace any existing lines with:
    
    ```yaml
    network:
      ethernets:
        enp0s3:
          dhcp4: no
          addresses: [192.168.10.10/24]
          nameservers:
            addresses: [8.8.8.8, 8.8.4.4]
          routes:
    		      - to: default 
    			      via: 192.168.10.1
    	version: 2
    ```
    
    ![Screenshot of the configuration file **`/etc/netplan/01-netcfg.yaml`** after update it**.**](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/2cd7d4c4-ce5b-4bb6-ba8e-908d12e58c2d.png)
    
    Screenshot of the configuration file **`/etc/netplan/01-netcfg.yaml`** after update it**.**
    
- Press **`Ctrl+X`**, then **`Y`** to save and exit.
- Apply the configuration using **`sudo netplan apply`**.
    
    ![Now we have a static ip (check it with ip a) and we are online.](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2016.png)
    
    Now we have a static ip (check it with ip a) and we are online.
    

With this configuration:

- **Network Interface**:
    - The system has one Ethernet interface named **`enp0s3`**.
- **IPv4 Configuration**:
    - **`dhcp4: no`**: This specifies that DHCP (Dynamic Host Configuration Protocol) is not being used for IPv4 address configuration on this interface.
    - **`addresses: [192.168.10.10/24]`**: This assigns the static IPv4 address **`192.168.10.10`** to the interface with a subnet mask of **`/24`**, which corresponds to a subnet mask of **`255.255.255.0`**, indicating that the first 24 bits are network bits and the remaining 8 bits are host bits.
    - **`nameservers`**: Specifies the DNS (Domain Name System) servers to be used by the system.
        - **`addresses: [8.8.8.8, 8.8.4.4]`**: This lists the DNS servers **`8.8.8.8`** and **`8.8.4.4`**, which are Google's public DNS servers.
- **Routing**:
    - **`routes`**: This section defines routing settings for the system.
        - **`to: default`**: This route is for the default gateway, meaning all traffic not destined for the local network will be sent to this gateway.
        - **`via: 192.168.10.1`**: This specifies that the default gateway for outbound traffic is at **`192.168.10.1`**.
- **Version**:
    - **`version: 2`**: This specifies the version of the Netplan configuration syntax being used. In this case, it's version 2.

This configuration sets up a static IPv4 address (**`192.168.10.10`**) with a subnet mask of **`/24`** on the **`enp0s3`** interface, specifies DNS servers, and defines a default gateway for outbound traffic.

### **Active Directory Server (Windows Server 2022)**

- Click "Start" > "Settings" > "Network & Internet" > "Ethernet."
- Click "Change adapter options."
- Right-click the adapter (likely labeled "Ethernet") and select "Properties."
- Select "Internet Protocol Version 4 (TCP/IPv4)" and click "Properties."
- Choose "Use the following IP address" and fill in:
    - **IP Address:** **`192.168.10.7`**
    - **Subnet Mask:** **`255.255.255.0`**
    - **Default Gateway:** **`192.168.10.1`**
- Click "OK" to apply the settings.
- Then you have to rename the pc. To do it search for  "This PC" > "Properties" > "Rename your PC" and set it to **`AADC01`**
- Do the same steps for the Windows pc (victim) → setup its IP to a prefered one and then rename its name to `**target-pc**`
    
    
    ![Change the IP address on the Victim machine](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2017.png)
    
    Change the IP address on the Victim machine
    
    ![Remame of the Victim machine](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2018.png)
    
    Remame of the Victim machine
    

### Kali Linux (Attacker)

![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2019.png)

![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2020.png)

---

# **Installation and Configuration of Services**

This section of the report outlines the detailed steps to install and configure key services such as Active Directory, Splunk, and Sysmon, along with the Splunk Universal Forwarder. These installations are crucial for setting up the project’s monitoring and security testing infrastructure.

## **Splunk Setup**

Splunk is a software platform used for monitoring, searching, analyzing, and visualizing machine-generated data in real-time.

### **Steps to Install and Configure Splunk:**

1. **Install Splunk on Ubuntu Server:**
    - Transfer the downloaded Splunk **`.deb`** file to your Ubuntu server using SCP or a similar tool.
    - Install Splunk by running:
        
        ```php
        sudo dpkg -i splunk-<version>-<build>.deb
        ```
        
    - Enable Splunk to start at boot:
        
        ```bash
        sudo /opt/splunk/bin/splunk enable boot-start
        ```
        
    - Start Splunk for the first time:
        
        ```bash
        sudo /opt/splunk/bin/splunk start
        ```
        
    - During the initial start, you will be prompted to set up an admin username and password.
    
    To access the Splunk Web Interface typically available at **`http://<Your-Splunk-Server-IP>:8000`**.
    
    ![Type 192.168.10.10:8000 to access to Splunk Web Interface](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2021.png)
    
    Type 192.168.10.10:8000 to access to Splunk Web Interface
    

## **Sysmon and Universal Forwarder**

Sysmon (System Monitor) is a Windows system service and device driver that monitors and logs system activity to the Windows event log, providing detailed information about process creations, network connections, and changes to file creation time.

### **Steps to Install Sysmon and Splunk Universal Forwarder**

1. **Install Sysmon on Windows Server and Windows 10:**
    - Download Sysmon from the Microsoft Sysinternals website ([https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)).
    - Download the file `sysmonconfig.xml` from the repo  https://github.com/olafhartong/sysmon-modular →
    - Install Sysmon by running the following command in powershell as administrator:
        
        ```css
        sysmon -i sysmonconfig.xml
        ```
        
        ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2022.png)
        
    
2. **Install Splunk Universal Forwarder on Windows Server and Windows 10:**
    - Download the Splunk Universal Forwarder installer for Windows ([https://www.splunk.com/en_us/download/universal-forwarder.html](https://www.splunk.com/en_us/download/universal-forwarder.html)).
        
        ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2023.png)
        
    - Run the installer and follow the setup wizard:
        - Create an administrator account with a random password
            
            ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2024.png)
            
        - Specify the Splunk receiver settings (IP of your Splunk server and receiving port, typically 9997).
            
            ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2025.png)
            
    
    ### **Instruct the splunk forwarder**
    
    - Using notepad with administrator save in `C:\Program Files\SplunkUniversalForwarder\etc\system\local` a file named `inputs.conf` with the contenent:
        
        <aside>
        📝 [WinEventLog://Application]
        
        index = endpoint
        
        disabled = false
        
        [WinEventLog://Security]
        
        index = endpoint
        
        disabled = false
        
        [WinEventLog://System]
        
        index = endpoint
        
        disabled = false
        
        [WinEventLog://Microsoft-Windows-Sysmon/Operational]
        
        index = endpoint
        
        disabled = false
        
        renderXml = true
        
        source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
        
        </aside>
        
    - Look for the Splunk forwarder service and modify its “startup type” → Services > search the SplunkForwarder > Properties > Log On > Log on as: Local System account
        
        
        ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2026.png)
        
        ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2027.png)
        
        ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2028.png)
        
    - And then restart the service
        
        ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2029.png)
        
    

These installations and configurations establish a foundational monitoring framework that captures detailed system activities and logs for security analysis, helping enforce security policies and detecting potential threats in real-time.

## Setup Splunk

- Using the **`http://<Your-Splunk-Server-IP>:8000`** login to the Splunk Web Interface
    
    ![Type 192.168.10.10:8000 to access to Splunk Web Interface](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2021.png)
    
    Type 192.168.10.10:8000 to access to Splunk Web Interface
    
- Now go to settings > indexes
    
    ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2030.png)
    
- All log files are sent to an index called endpoind (we specify it in `inputs.conf`) so now we create this → “New index” > name it `endpoint`
    
    
    ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2031.png)
    
    ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2032.png)
    
- Finnaly we have to ensure that ur splunk server is able to recive the data → Forwarding and reciving > Configure reciving > New reciving port > listen on port 9997
    
    
    ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2033.png)
    
    ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2034.png)
    
    ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2035.png)
    
    ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2036.png)
    

## **Active Directory Installation**

Active Directory (AD) is a directory service developed by Microsoft for Windows domain networks. It involves setting up a Domain Controller (DC) that authenticates and authorizes all users and computers within a Windows domain network.

### **Steps to Install Active Directory:**

1. **Prepare the Windows Server:**
    - Ensure your Windows Server 2022 VM is fully updated through 'Windows Update' before proceeding.
2. **Install Active Directory Domain Services (AD DS):**
    - Open 'Server Manager' on your Windows Server.
    - Click on 'Add roles and features' and click 'Next' through the wizard until you reach the 'Roles' page.
    - Check the box for 'Active Directory Domain Services'. When prompted to add features that are required for AD DS, click 'Add Features', then 'Next'.
        
        
        ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2037.png)
        
        ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2038.png)
        
    - Continue clicking 'Next' without changing default selections until you reach the 'Install' button. Click 'Install'.
3. **Promote the server to a domain controller:**
    - After installation, in the 'Server Manager' dashboard, you will see a notification flag near the top-right. Click on it and select 'Promote this server to a domain controller'.
        
        ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2039.png)
        
    - Select 'Add a new forest' and type the Root domain name (e.g., `h0rox.local`).
        
        ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2040.png)
        
    - Set a DSRM (Directory Services Restore Mode) password—this is crucial for recovery operations.
        
        ![Set a new Password = Password1234](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2041.png)
        
        Set a new Password = Password1234
        
    - Follow through the wizard, leave other options at their defaults, and click 'Next' until you can click 'Install'.
    - Once the installation completes, the server will reboot.

### **Post-Installation Configuration**

After rebooting, you can log in with the domain admin credentials to configure user accounts, groups, and policies as needed.

### Creation of new Organizational Unit and Users

- Tools > Active Directory Users and Computers
- Click on the domain > New > Organizational Unit
    
    ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2042.png)
    
- Create a new Organizational Unit (for example **`IT`**)
- In this new Organizational Unit (`**IT**`) new > User and then create a new user with name, surname, username and password
- Do this for another time to create another Organizational Unit (**`HR`**) and another user
    
    
    ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2043.png)
    
    ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2044.png)
    
    ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2045.png)
    
    ![Password1234](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2046.png)
    
    Password1234
    

### Join in Domain

So now, after we create a new domain we have to connect our pc to this new domain

- First change the DNS server address: we have to update our DNS server address to the one of the AD server (`192.168.10.7`)
    
    
    ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2047.png)
    
    ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2048.png)
    
- Then change the domain: PC > Advance system settings > Computer Name > Change > change the domain to `yourdomain.LOCAL` and then enter the credentials.
    
    
    ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2049.png)
    
    ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2050.png)
    
- Finally, login as a domain user: Other user > enter the credientials
    
    ![Untitled](Active%20Directory%20Project%2036cf4f04528d455bb355ff23c5aa72f2/Untitled%2051.png)
    

---

# **Security Testing and Monitoring**

This section of the report outlines the steps for conducting security testing using Kali Linux to simulate attacks and Splunk for monitoring and analyzing system events and logs, capturing the results of security testing in real-time.

### **1. LLMNR/NBT-NS Poisoning**

- **Description:** LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) are protocols used to identify hosts in a network where DNS fails. Poisoning these protocols can allow attackers to intercept traffic and steal credentials by impersonating other hosts.
- **Tools:** Responder

### **2. SMB Relay Attacks**

- **Description:** This attack involves intercepting legitimate SMB (Server Message Block) authentication requests and relaying them to access other services on the network using the victim's credentials, effectively bypassing authentication mechanisms.
- **Tools:** Metasploit, Impacket

### **3. IPv6 DNS Takeover Attacks**

- **Description:** By exploiting the IPv6 configuration or weaknesses in DNS, an attacker could redirect DNS traffic to malicious servers, leading to data interception or malware distribution.
- **Tools:** Custom scripts, network manipulation tools

### **4. Pass-the-Password**

- **Description:** This involves using captured plain-text passwords or hashes to authenticate to network services directly, typically after obtaining them through phishing or other means.
- **Tools:** Metasploit, Hydra

### **5. Pass-the-Hash**

- **Description:** Instead of needing the user's plain password, attackers use the hash of a user’s password to authenticate to services that use NTLM (Windows challenge/response) authentication.
- **Tools:** Metasploit, Mimikatz

### **6. Token Impersonation**

- **Description:** After gaining local administrator access, an attacker can impersonate the security token of a logged-on user (e.g., services or administrative accounts), allowing them to execute commands with the same rights as the impersonated user.
- **Tools:** Incognito (Metasploit), Mimikatz

### **7. Kerberoasting**

- **Description:** This attack exploits the Kerberos protocol's TGS (Ticket Granting Service) by requesting service tickets for every known user and then attempting to crack these tickets offline to find passwords of accounts running services.
- **Tools:** Impacket, Mimikatz

### **8. Golden Ticket**

- **Description:** After gaining domain admin rights, an attacker can create a TGT (Ticket Granting Ticket) that allows them access to any service on the domain. This is a severe form of persistence and lateral movement technique.
- **Tools:** Mimikatz

### **9. PowerView / BloodHound / Other Enumeration Tools**

- **Description:** These tools are used for network reconnaissance to identify complex attack paths that would otherwise be difficult to detect.
    - **PowerView** is a PowerShell tool used to gain a detailed understanding of the network environment.
    - **BloodHound** uses graph theory to reveal hidden and often unintended relationships within Active Directory environments.
- **Tools:** PowerView, BloodHound

### **10. Credential Dumping with Mimikatz**

- **Description:** Mimikatz is a powerful tool used to extract plaintext passwords, hash, PIN code, and kerberos tickets from memory. Credential dumping is the process of extracting credential material from Windows systems.
- **Tools:** Mimikatz

---

# **Conclusion**

This report has systematically covered the essential components and procedures required to establish a functional and secure Active Directory lab environment. By following the detailed steps outlined in the preceding chapters, you have set up an isolated network with VirtualBox, configured vital services like Active Directory and Splunk, and conducted security testing through simulated attacks using Kali Linux.

## **Project Review**

The project's primary objective was to create a hands-on learning environment that mirrors real-world configurations and challenges faced in IT and cybersecurity roles. Each component—from the creation of virtual machines and network setup to the installation of Active Directory, Splunk, and Sysmon—has been designed to provide you with practical skills in managing and securing networked systems. The inclusion of security testing with Kali Linux emphasized the importance of proactive security measures and the effectiveness of monitoring tools like Splunk in detecting and responding to potential threats.

## **Skills Gained**

Through this project, you have developed a range of technical competencies:

- **System Administration:** You have gained experience in setting up and configuring Windows servers, managing Active Directory, and understanding network configurations.
- **Cybersecurity Practices:** The project enhanced your understanding of network security principles, attack methodologies, and defensive tactics, crucial for anyone pursuing a career in cybersecurity.
- **Problem-solving:** The troubleshooting steps included in the report have equipped you with problem-solving skills that are vital for diagnosing and resolving network and security-related issues.
- **Analytical Skills:** By using Splunk for data analysis and monitoring, you've learned how to extract actionable insights from large volumes of data—skills that are highly valued in many IT and security roles.

---
