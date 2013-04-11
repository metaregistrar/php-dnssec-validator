<?php
include_once(dirname(__FILE__).'/DNS/dnsProtocol.php');

if ($argc<=1)
{
    echo "Usage: validate <domainname>\n";
    exit(-1);
}
$domainname = $argv[1];
try
{
    validateDomain($domainname);
    echo "$domainname dnssec validation succesful\n";
}
catch (DnsException $e)
{
    echo "ERROR: ".$e->getMessage()."\n";
}

function validateDomain($domainname)
{
    $domainname = strtolower($domainname);
    $dns = new dnsProtocol(false);
    $tld = substr($domainname,strpos($domainname,'.')+1);
    $dnsservers = $dns->registrynameservers($tld);
    if (!is_array($dnsservers))
    {
        throw new DnsException("DNSSEC validation not supported yet for the domain name ".$domainname);
    }
    foreach ($dnsservers as $dnsserver)
    {
        $dns->setServer($dnsserver);
        $result = $dns->Query($domainname,'NS');
        if ($result->getNameserverResultCount()>0)
        {
            $ns = $result->getNameserverResults();
            foreach ($ns as $n)
            {
                $nameservers[]=$n->getNameserver();
            }
            $result = $dns->Query($domainname,'DS');
            if ($result->getResourceResultCount()==0)
            {
                #
                # No DS record found at parent: domain is not secured
                #
                return false;
            }
            else
            {
                $ds = $result->getResourceResults();
                foreach ($ds as $d)
                {
                    $pk['key']=$d->getKey();
                    $pk['keytag']=$d->getKeytag();
                    $pk['algorithm']=$d->getAlgorithm();
                    $pk['matched']=false;
                    $parentkeys[]=$pk;
                }
            }
            break;
        }
    }

    #
    # Retrieve all necessary records
    #

    foreach ($nameservers as $ns)
    {
        $dns->setServer($ns);
        $result = $dns->Query($domainname,'RRSIG');
        if ($result->getResourceResultCount()==0)
        {
            throw new DnsException("No RRSIG records found on ".$ns." for domain name ".$domainname);
        }
        else
        {
            $rrsigs = $result->getResourceResults();
            foreach ($rrsigs as $rrsig)
            {
                if ($rrsig->getTypeCovered()=='SOA')
                {
                    $rr[$ns]=$rrsig;
                }
            }
        }
        $result2 = $dns->Query($domainname,'DNSKEY');
        if ($result2->getResourceResultCount()==0)
        {
            throw new DnsException("No DNSKEY records found on ".$ns." for domain name ".$domainname);
        }
        else
        {
            $ds = $result2->getResourceResults();
            foreach ($ds as $childkey)
            {
                if ($childkey->getSep())
                {
                    $dnskey[$ns]=$childkey;
                }
            }
        }
        if (!$rr[$ns])
        {
            throw new DnsException("No matching resource record type SOA found on ".$ns." for ".$domainname);
        }
        if (!$dnskey[$ns])
        {
            throw new DnsException("No matching DNSKEY record found with SEP flag enabled on ".$ns." for $domainname");
        }
        validateRRSIG($domainname, $rr[$ns], $ds);
        validateDNSKEY($domainname, $dnskey[$ns], $parentkeys);
    }
    return true;
}


function validateDNSKEY($domainname, dnsDNSKEYresult $dnskey, $parentkeys)
{
    $validkeyfound = false;
    foreach ($parentkeys as $index=>$parentkey)
    {
        if ($dnskey->getKeytag()==$parentkey['keytag'])
        {
            #
            # Algorithms for SEP key and parent key must match
            #
            $validkeyfound = true;
            $parentkeys[$index]['matched']=true;
            if ($parentkey['algorithm']!=$dnskey->getAlgorithm())
            {
                throw new DnsException("Parent ($parentkey[algorithm]) and child (".$dnskey->getAlgorithm().") algorithms for key ".$dnskey->getKeytag()." do not match for ".$domainname);
            }
        }
        else
        {
            $algo = $dns->algorithm($dnskey->getAlgorithm());
        }

    }
    foreach ($parentkeys as $parentkey)
    {
        if (!$parentkey['matched'])
        {
            throw new DnsException('No match found for parent key '.$parentkey['keytag']);
        }
    }
    if (!$validkeyfound)
    {
        throw new DnsException("No valid key with SEP found for domain name ".$domainname);
    }
}


function validateRRSIG($domainname, dnsRRSIGresult $rrsig, $ds)
{
    #
    # Inception timestamp must lie in the past
    #
    if ($rrsig->getInceptionTimestamp() > time())
    {

        throw new DnsException("Key ".$rrsig->getKeytag()." for domain name ".$domainname." is not yet valid: starts on ".$rrsig->getInceptionDate());
    }
    #
    # Expiration timestamp must lie in the future
    #
    if ($rrsig->getExpirationTimestamp() < time())
    {
        throw new DnsException("Key ".$rrsig->getKeytag()." for domain name ".$domainname." has expired at ".$rrsig->getExpirationDate());
    }
    #
    # Signer name must be equal to domain name
    #
    if ($rrsig->getSignername()!=$domainname)
    {
        throw new DnsException("RRSIG signer name ".$rrsig->getSignername()." for domain name ".$domainname." is incorrect");
    }
    #
    # Keytag for signing must exist in the DNSKEY records
    #
    $keyfound = false;
    foreach ($ds as $childkey)
    {
        if ($childkey->getKeytag()==$rrsig->getKeytag())
        {
            $keyfound = true;
        }
    }
    if (!$keyfound)
    {
        throw new DnsException("Keytag ".$rrsig->getKeytag()." cannot be found in the DNSKEY records for domain name ".$domainname." to validate RRSIG");
    }
}
