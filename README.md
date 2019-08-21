# Utilizing snapshots with FreeBSD 12.0 Part 1

### Introduction

In this tutorial we build a core inventory of snapshots that will serve as templates for all of our FreeBSD droplets. These will enable us to quickly deploy a wide variety of services on-demand. The end result will be a dynamic new component added to our infrastructure that is flexible, scalable, and compatible with almost any type of workflow. Maintaining a library of production-ready snapshots also delivers some of the conveniences offered by container-applications, without the complexity of a container-orchestrator.

## Goals

* Build a core inventory of FreeBSD snapshots
* Prepare for the next tutorials

## Prerequisites

* A Unix-like machine (BSD, Linux, or Mac)
* A Digital Ocean account with an [ssh-keypair](https://www.digitalocean.com/docs/droplets/how-to/connect-with-ssh), an [authorization token](https://www.digitalocean.com/docs/api/create-personal-access-token), and a [cloud-firewall](https://www.digitalocean.com/docs/networking/firewalls/quickstart) that only allows inbound SSH traffic.
* The [jq](https://stedolan.github.io/jq) JSON processor

<$>[note]
**Note:** We utilize the amazing **jq** JSON processor for parsing and manipulating **APIv2** responses. Many tools can achieve this, however **jq** is lightweight, has zero dependencies, is written in portable C, and has stellar documentation. You can install it on your workstation with apt, brew, dnf, pacman, pkg, ports, and more.
<$>

<$>[note]
**Note:** This project uses standard 1G droplets, which are $5 per month. After we create our snapshots, the droplets can be deleted, unless you want to keep them. Snapshots, at the time of this writing, are $.05/GB per month. We create 3 snapshots that are less than 2GB, which equates to less than $1 per month.
<$>

## Step 1 - Create the freebsd-base droplet

We need to configure a droplet before we can create a snapshot. Let's create our first droplet and name it **freebsd-base**, using a standard 1G image. Our **freebsd-base** droplet will be the building block for all of our snapshots so it is imperative that we get it right. Throughout this lesson we rely heavily on the [APIv2](https://developers.digitalocean.com/documentation/v2), therefore your [authorization token](https://www.digitalocean.com/docs/api/create-personal-access-token) must be configured. 

Query the APIv2 for your account's ssh-key information and cache the response:
```command
curl -X GET -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" "https://api.digitalocean.com/v2/account/keys" > /tmp/do-ssh-keys-cache.json
```
View the cache with **jq**:
```command
jq < /tmp/do-ssh-keys-cache.json
```
Extract the ssh-key ID:
```command
jq '.ssh_keys[0] | .id' < /tmp/do-ssh-keys-cache.json
```
Export the ssh-key ID into our shell environment:
```command
echo "export DO_SSH_KEY_ID=$(jq '.ssh_keys[0] | .id' < /tmp/do-ssh-keys-cache.json)" >> ~/.profile 
```
Reload the shell environment:
```command
. ~/.profile
```
Sanity check:
```command
echo $DO_SSH_KEY_ID
```
Add the ssh-key ID to a POST request and create the droplet. We're using the San Francisco region, however you should pick the region that best suits your needs. A list of available regions can be found at the [APIv2 regions tab](https://developers.digitalocean.com/documentation/v2/#regions), or in the [control panel](https://cloud.digitalocean.com/login). Just remember to update the relevant command options during droplet creation, including the `"region"` and the `"tags"`:
```command
curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"name":"freebsd-base","region":"sfo2","size":"s-1vcpu-1gb","image":"freebsd-12-x64-zfs", "ssh_keys":['$DO_SSH_KEY_ID'], "tags":["base","sfo2"]}' "https://api.digitalocean.com/v2/droplets"
```

<$>[warning]
**Warning:** Attach the droplet to a [cloud-firewall](https://www.digitalocean.com/docs/networking/firewalls/quickstart) from the [control panel](https://cloud.digitalocean.com/login) before proceeding or else the droplet may be insecurely exposed to the internet. The [cloud-firewall](https://www.digitalocean.com/docs/networking/firewalls/quickstart) should only allow SSH inbound traffic. Later we will implement our own firewall.
<$>

Query the [APIv2](https://developers.digitalocean.com/documentation/v2) for the droplet's meta-data and cache the response:
```command
curl -X GET -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" "https://api.digitalocean.com/v2/droplets?tag_name=base" > /tmp/do-droplets-base-cache.json
```
Extract the droplet's name and IP address:
```command
jq '.droplets[0] | {name,networks}' < /tmp/do-droplets-base-cache.json
```
SSH into the droplet with the IP address:
```command
ssh root@XXX.XX.X.XX
```

We should now be logged-in as **root@freebsd-base**. Have a look around but use extreme caution with root access. Until we add users to the system, root access is our only option.

## Step 2 - User Management

We will now implement some mandatory user-related configurations on our **freebsd-base** droplet. Having these settings built-in to every droplet will prevent us from having to repeat ourselves for every droplet, which leaves too much room for error, hence becoming a security risk.

### Strengthen the password hashing algorithm to blowfish

We want really strong passwords on our servers. The default hashing algorithm is SHA512. Let's switch to the stronger Blowfish algorithm. This can be accomplished by modifying the `/etc/login.conf` file.

Make a copy of `/etc/login.conf`:
```super_user
cp /etc/login.conf /etc/login.conf.orig
```
Change the hashing algorithm to **Blowfish**:
```super_user
sed -i -e 's/sha512/blf/' /etc/login.conf
```
Sanity check:
```super_user
diff /etc/login.conf /etc/login.conf.orig
```
The system maintains a `/etc/login.conf.db` that must be updated when `/etc/login.conf` is modified. This is accomplished by running the `cap_mkdb` command.
Update `/etc/login.conf.db`:
```super_user
cap_mkdb /etc/login.conf
```

### Use PAM to enforce longer passwords with a mixture characters, symbols, and numbers

Make a copy of `/etc/pam.d/passwd`:
```super_user
cp /etc/pam.d/passwd /etc/pam.d/passwd.orig
```
Edit the file:
```super_user
vim /etc/pam.d/passwd
```
Add the following options to the **pam_passwdqc.so** module:
```
password        requisite       pam_passwdqc.so         min=disabled,disabled,disabled,15,12 similar=deny retry=3 enforce=users
```
Create a root password. There will be a message that reflects our PAM configuration:
```super_user
passwd
```
Create a sudo user named **admin0**:
```super_user
adduser
```
```
Username: admin0
Full name:
'' ''
'' ''
'' ''
Select the defaults, enter a password, and do not create any other users.
```
Create the sudo group and add **admin0**:
```super_user
pw groupadd sudo
```
```super_user
pw groupmod sudo -m admin0
```
Edit the **sudoers** file:
```super_user
visudo
```
```
Uncomment this line: %sudo ALL=(ALL) ALL
```

### Implement the sshd configuration

Make a copy of `/etc/sshd_config`:
```super_user
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.orig
``` 
Modify `/etc/ssh/sshd_config`:
```super_user
vim /etc/ssh/sshd_config
```
Match the following settings:
```
PubKeyAuthentication yes
PasswordAuthentication no
PermitRootLogin no
```
Copy the public ssh-key from `~/.ssh` to `/home/admin0/.ssh`:
```super_user
rsync --archive --chown=admin0:admin0 ~/.ssh /home/admin0
```
Sanity checks:
```super_user
cat /home/admin0/.ssh/authorized_keys
```
Verify that the ownership and permissions are correct:
```super_user
ls -l /home/admin0/.ssh/authorized_keys
```

If it prints the public key, and the ownership and permissions are correct, we're good-to-go! The permissions of `/home/admin0/.ssh/authorized_keys` should be 0600. Don't logout yet because we need to configure our firewall.

## Step 3 - Configure the firewall

Having a working firewall baked in to every droplet is a critical security measure. We want immediate protection the moment a droplet is created without having to manually intervene. The FreeBSD base system ships with three firewalls: 1) IPF, 2) IPFW, and 3) PF, none of which are enabled by default. For this tutorial, we choose the renown [PF](https://www.openbsd.org/faq/pf), which is authored and maintained by the [OpenBSD](https://www.openbsd.org) project. [PF](https://www.openbsd.org/faq/pf) is known for its user-friendliness, simple-syntax, and its astonishing power. It is also a dependency of many other native BSD tools that you will likely encounter as an administrator. If you prefer IPFW or IPF instead, simply create a ruleset, and enable the one you prefer in `/etc/rc.conf`. The [FreeBSD Handbook](https://www.freebsd.org/doc/en_US.ISO8859-1/books/handbook) is the authoritative source of guidance for this task.

Our **freebsd-base** droplet only requires a simple firewall that permits inbound SSH traffic. The outbound rules include a minimal list of ports, allowing access to some basic services from the internet. We also add a few perks such as packet normalisation, antispoofing protection, logging, safe icmp usage, and more. This ruleset was inspired by a mixture of excellent sources, including the [FreeBSD Handbook](https://www.freebsd.org/doc/en_US.ISO8859-1/books/handbook), the [PF User's Guide](https://www.openbsd.org/faq/pf), and [The Book of PF](https://www.amazon.com/Book-PF-No-Nonsense-OpenBSD-Firewall/dp/1593275897) by Peter Hansteen.

Create the PF configuration file:
```super_user
vim /etc/pf.conf
```
Add the following ruleset:
```
public_if = "vtnet0"
tcp_out = "{ 22 53 80 123 443 }"
udp_out = "{ 53 123 }"
icmp_out = "{ echoreq unreach }"
icmp6_out = "{ echoreq unreach timex paramprob }"
table <blackhats> { 0.0.0.0/8 10.0.0.0/8 127.0.0.0/8 169.254.0.0/16    \
	 	   172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 224.0.0.0/3 \
	 	   192.168.0.0/16 198.18.0.0/15 198.51.100.0/24        \
	 	   203.0.113.0/24 }
set skip on lo0
# Normalise traffic
scrub in all fragment reassemble no-df max-mss 1440
antispoof quick for { egress $public_if }
block in quick on egress from <blackhats> to any
block return out quick on egress from any to <blackhats>
block return log on $public_if all
# This line opens up ports
pass in log quick on $public_if proto tcp to port { 22 }
pass out proto tcp to port $tcp_out
pass out proto udp to port $udp_out
# Allow ping
pass inet proto icmp icmp-type $icmp_out
pass inet6 proto icmp6 icmp6-type $icmp6_out
```
Make a copy of `/etc/pf.conf`:
```super_user
cp /etc/pf.conf /etc/pf.conf.orig
```
Enable PF:
```super_user
sysrc pf_enable=yes
sysrc pflog_enable=yes
```
Sanity check:
```super_user
cat /etc/rc.conf
```
Reboot the droplet:
```super_user
reboot
```

Detach the cloud-firewall from the droplet in the control panel and give it a minute or so for everything to update. At this point we should verify that our settings are working.

We should *not* be able to log in as root:
```
$ ssh root@XXX.XX.XXX.XXX
# It will prompt for a password, but deny us after 3 tries
```
SSH in to the droplet as **admin0**:
```
$ ssh admin0@XXX.XXX.XX.XXX
$ whoami
# We should be logged in as admin0
```
Ensure that we can gain root access through the sudo user:
```command
sudo su
```
Exit out of root:
```super_user
exit
```
Let's ensure that PF is working:
```
$ sudo pfctl -f /etc/pf.conf
# If there are no messages, we're okay!
```
Check out some PF stats:
```command
sudo pfctl -si
```
Test `ping` and `traceroute`:
```command
ping 8.8.8.8
traceroute -I 8.8.8.8
```

## Step 4 - Configure time settings

If our servers do not have accurate time settings, it will lead to serious trouble. Here we will setup **ntpd**, which is part of the FreeBSD base system. We will use the Coordinated Universal Time (UTC) system, which is the primary standard throughout the world.

Select time system:
```
$ sudo tzsetup
# Select UTC
```
Make a copy of `/etc/ntp.conf`:
```command
sudo cp /etc/ntp.conf /etc/ntp.conf.orig
```
Configure `/etc/ntp.conf`:
```command
sudo vim /etc/ntp.conf
```
Append the file with the following:
```
server 0.pool.ntp.org
server 1.pool.ntp.org
server 2.pool.ntp.org
server 3.pool.ntp.orb

driftfile /var/db/ntp/ntp.drift
```
Enable **ntpd**:
```command
sudo sysrc ntpd_enable="YES"
sudo sysrc ntpd_sync_on_start="YES"
```

## Step 5 - Disable cloud-init and reboot the droplet

Snapshots include a droplet's [meta-data](https://www.digitalocean.com/docs/droplets/resources/metadata), which includes a droplet's hostname. Our goal is to spin-up droplets from pre-configured snapshots instead of starting from scratch every time. Since a snapshot's [meta-data](https://www.digitalocean.com/docs/droplets/resources/metadata) contains its original hostname, it will give that hostname to any droplet created from it, with the help of [cloud-init](https://cloud-init.io). Therefore we disable [cloud-init](https://cloud-init.io), which is okay for our purposes because we're not using it to configure our droplets. When we create new droplets from our snapshots, we still have to update the hostname (you can script it!), but the changes will survive a reboot.

Disable cloud-init:
```command
sudo sysrc cloudinit_enable="NO"
```
Sanity check:
```command
cat /etc/rc.conf
```
Reboot the droplet:
```
$ sudo reboot
# Give it a minute or so to finish
```
SSH back into the droplet
```command
ssh admin0@XXX.XX.XXX.XXX
```
Test **ntpd**:
```
$ date
# It should be perfect!
$ ntpq -pn
# You should see a table of random time servers
# Visit https://www.ntppool.org
```

Don't logout yet, we should remain logged-in for the next step.

## Step 6 - Create the freebsd-base-snapshot

<$>[warning]
**Warning:** droplets must be completely powered-off before [creating snapshots](https://www.digitalocean.com/docs/images/snapshots/how-to/snapshot-droplets) or else corruption can occur. Droplets should be powered-off from the command-line. In the control panel GUI you'll find a graphical on-off-switch that will display 'off' when it finishes.
<$>

Poweroff the droplet:
```
$ sudo poweroff
# Give it time to completely power-off
# There's a graphical on-off switch in the control panel that will display 'off' when it is completely finished
```

[Create the snapshot](https://www.digitalocean.com/docs/images/snapshots/how-to/snapshot-droplets) in the [control panel](https://cloud.digitalocean.com/login) from the **freebsd-base** droplet, naming it **freebsd-base-snapshot**. Give it a minute or so to finish. Congratulations, the first snapshot is done! We can now use it to spin-up new droplets without having to repeat any of the configuration steps above. All of the settings will be active. Our new **freebsd-base-snapshot** is a foundational piece of our infrastructure.

We still have one more step. Let's export the ID of our snapshot into our shell environment so that we can create droplets quickly from the command-line.

Query the [APIv2](https://developers.digitalocean.com/documentation/v2) for the snapshot's [meta-data](https://www.digitalocean.com/docs/droplets/resources/metadata) and cache the response:
```command
curl -X GET -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" "https://api.digitalocean.com/v2/snapshots" > /tmp/do-snapshots-cache.json
```
View the cache:
```command
jq < /tmp/do-snapshots-cache.json
```
Export the snapshot ID into our shell environment:
```command
echo "export FREEBSD_BASE_SNAPSHOT_ID="$(jq '.snapshots[0] | .id' < /tmp/do-snapshots-cache.json)"" >> ~/.profile
```
Reload our shell environment:
```command
. ~/.profile
```
Sanity check:
```command
echo $FREEBSD_BASE_SNAPSHOT_ID
```

## Step 7 - Create the freebsd-base-pkgs droplet

Next we build a snapshot that will be used specifically for **packages** projects. Choosing between **packages** and **ports** is a common crossroads in FreeBSD systems. Whatever your needs are, ports should only be used when there are special needs. If we build a piece of software from ports, any additional software that it interacts with should also be built from ports. For this reason, we will prepare ourselves for either situation by building a snapshot for both **packages** and **ports**. Hence we will build a **freebsd-base-pkgs** droplet and make a snapshot out of it.

### Create the freebsd-base-pkgs droplet:

Create the droplet using freebsd-base-snapshot ID, naming it **freebsd-base-pkgs**:
```command
curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"name":"freebsd-base-pkgs","region":"sfo2","size":"s-1vcpu-1gb","image":"'$FREEBSD_BASE_SNAPSHOT_ID'", "ssh_keys":['$DO_SSH_KEY_ID'], "tags":["base-pkgs", "sfo2"]}' "https://api.digitalocean.com/v2/droplets"
```

Give it a minute or so to finish. Remember, no need to worry about a firewall anymore because PF is enabled!

Query and cache the droplet's meta-data according to its tags:
```command
curl -X GET -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" "https://api.digitalocean.com/v2/droplets?tag_name=base-pkgs" > /tmp/do-droplets-base-pkgs-cache.json
```
Parse the objects in "droplets" array for the droplet's name and network information:
```command
jq '.droplets[0] | {name,networks}' < /tmp/do-droplets-base-pkgs-cache.json
```
SSH into the droplet with the IP address:
```command
ssh admin0@XXX.XXX.XX.XXX
```
Update the hostname:
```command
sudo sysrc hostname="freebsd-base-pkgs"
```
Sanity check:
```command
cat /etc/rc.conf
```
Confirm that pkgs is up-to-date
```command
sudo pkg update
```
Reboot the droplet
```
sudo reboot
Give it a minute or so to finish
```

In reality **freebsd-base-pkgs** is no different from **freebsd-base**, but that's okay! Categorizing our snapshots can only help us, and could even save us in the event of a catastrophe, such as accidentally deleting a snapshot. At least we'll have some options to recover with! We will protect **freebsd-base** by not using it much, reserving it for emergencies. The cost of maintaing multiple snapshots pales in comparison to what they can achieve.

## Step 8 - Create the freebsd-base-pkgs snapshot

Hopefully by now it's becoming clear where we are going with this. We've built our **packages** droplet, now we make a snapshot out of it named **freebsd-base-pkgs-snapshot**. After we create the snapshoot, all future droplets for **packages** projects will be created from our snapshot. Let's proceed and create the snapshot.

<$>[warning]
**Warning:** droplets must be completely powered-off before [creating snapshots](https://www.digitalocean.com/docs/images/snapshots/how-to/snapshot-droplets) or else corruption can occur. Droplets should be powered-off from the command-line. In the control panel GUI you'll find a graphical on-off-switch that will display 'off' when it finishes.
<$>

Poweroff the droplet:
```
$ ssh admin0@XXX.XXX.XX.XXX
$ sudo poweroff
# Give it time to completely finish
```

After it finishes powering-off, [Create the snapshot](https://www.digitalocean.com/docs/images/snapshots/how-to/snapshot-droplets) in the [control panel](https://cloud.digitalocean.com/login) from the **freebsd-base-pkgs** droplet, naming it **freebsd-base-pkgs-snapshot**. Give it a minute or so to finish. Congratulations, the second snapshot is done! We can now use it to spin-up new droplets for packages projects without having to repeat any of the configuration steps above.

### Export the snapshot ID into our shell environment

Query and cache our snapshot's meta-data:
```command
curl -X GET -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" "https://api.digitalocean.com/v2/snapshots" > /tmp/do-snapshots-cache.json
```
Parse the name and ID from the appropriate array objects:
```command
jq '.snapshots[1] | {name,id}' < /tmp/do-snapshots-cache.json
```
If that looks okay, export the ID:
```command
echo "export FREEBSD_BASE_PKGS_SNAPSHOT_ID="$(jq '.snapshots[1] | .id' < /tmp/do-snapshots-cache.json)"" >> ~/.profile
```
Reload the shell environment 
```command
$ . ~/.profile
```
Sanity check:
```command
echo $FREEBSD_BASE_PKGS_SNAPSHOT_ID
```

## Step 9 - Create the freebsd-base-ports droplet

As mentioned above, there will be times when the packages repository does not meet our requirements. We could have a special compile-time dependency, or maybe a piece of software simply doesn't exist in the packages repository. As we also mentioned above, we try to maintain a degree of separation between **packages** and **ports** projects, which is precisely why we are building a snapshot for both. We've already built our packages snapshot, now let's build a ports snapshot. Once again we build off of the **freebsd-base-snapshot**. This will make more sense below.

Create the **freebsd-base-ports** droplet using the **freebsd-base-snapshot** ID:
```command
curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"name":"freebsd-base-ports","region":"sfo2","size":"s-1vcpu-1gb","image":"'$FREEBSD_BASE_SNAPSHOT_ID'", "ssh_keys":['$DO_SSH_KEY_ID'], "tags":["base-ports","sfo2"]}' "https://api.digitalocean.com/v2/droplets"
```
Query and cache the droplet's meta-data according to its tag:
```command
curl -X GET -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" "https://api.digitalocean.com/v2/droplets?tag_name=base-ports" > /tmp/do-droplets-base-ports-cache.json
```
Parse the objects in "droplets" array for the name and network information:
```command
jq '.droplets[0] | {name,networks}' < /tmp/do-droplets-base-ports-cache.json
```
SSH into the droplet with the IP address:
```command
ssh admin0@XXX.XXX.XX.XXX
```
Update the hostname:
```command
sudo sysrc hostname="freebsd-base-ports"
```
Sanity check:
```command
cat /etc/rc.conf
```
Install the ports tree:
```
$ sudo portsnap fetch
$ sudo portsnap extract
# Go get a cup of coffee, this will take a while!
$ sudo portsnap update
```
Reboot the droplet
```
$ sudo reboot
# Give it a minute or so to finish
```
Verify that we have a ports tree:
```
$ ssh admin0@XXX.XXX.XX.XXX
$ ls /usr/ports
```

Don't logout yet.

## Step 10 - Create the freebsd-base-ports snapshot

<$>[warning]
**Warning:** droplets must be completely powered-off before [creating snapshots](https://www.digitalocean.com/docs/images/snapshots/how-to/snapshot-droplets) or else corruption can occur. Droplets should be powered-off from the command-line. In the control panel GUI you'll find a graphical on-off-switch that will display 'off' when it finishes.
<$>

Poweroff the droplet:
```
$ sudo poweroff
# Give it time to completely finish
```

Now [Create the snapshot](https://www.digitalocean.com/docs/images/snapshots/how-to/snapshot-droplets) in the [control panel](https://cloud.digitalocean.com/login) from the **freebsd-ports-droplet**, naming it **freebsd-base-ports-snapshot**. Give it a minute or so to finish. Congratulations, our third snapshot is done! We can now use our ports snapshot to spin-up droplets on-the-fly for ports-related projects. All of our configuration will remain intact.

### Export the snapshot ID into our shell environment

Query and cache the snapshot's meta-data:
```command
curl -X GET -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" "https://api.digitalocean.com/v2/snapshots" > /tmp/do-snapshots-cache.json
```
Parse the name and ID from the appropriate array objects:
```command
jq '.snapshots[2] | {name,id}' < /tmp/do-snapshots-cache.json
```
Export the ID into our shell environment:
```command
echo "export FREEBSD_BASE_PORTS_SNAPSHOT_ID="$(jq '.snapshots[2] | .id' < /tmp/do-snapshots-cache.json)"" >> ~/.profile
```
Reload the shell environment:
```command 
. ~/.profile
```
Sanity check 
```command
echo $FREEBSD_BASE_PORTS_SNAPSHOT_ID
```

## Conclusion

We have now added an exciting new component to our infrastructure. It is easy to imagine the myriad ways in which our snapshots can be integrated into other workflows. Snapshots are a robust and secure method of pre-configuring droplets. In the next lesson we will apply these concepts to a webserver, and build a trivial web-application that parses [meta-data](https://www.digitalocean.com/docs/droplets/resources/metadata) and displays it in an html page. You can check out a demo [here](http://snaps.chickenkiller.com). The demo is hosted on a free subdomain provided by an awesome domain sharing project known as [FreeDNS](https://freedns.afraid.org). Since it is only a static page that does not exchange any data, we are not using SSL. There are also some sandboxing features built into the webserver to strengthen security. Thank you for taking this tutorial. See you in the next one!


