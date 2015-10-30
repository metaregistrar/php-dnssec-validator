<?php
namespace Metaregistrar\DNS {
    class dnsTypes
    {
        var $types_by_id;
        var $types_by_name;

        private function AddType($id, $name)
        {
            $this->types_by_id[$id] = $name;
            $this->types_by_name[$name] = $id;
        }

        function __construct()
        {
            $this->types_by_id = array();
            $this->types_by_name = array();

            $this->AddType(1, "A");
            $this->AddType(2, "NS");
            $this->AddType(5, "CNAME");
            $this->AddType(6, "SOA");
            $this->AddType(12, "PTR");
            $this->AddType(13, "HINFO");
            $this->AddType(14, "MINFO");
            $this->AddType(15, "MX");
            $this->AddType(16, "TXT");
            $this->AddType(17, "RP");
            $this->AddType(18, "AFSDB");
            $this->AddType(19, "X25");
            $this->AddType(20, "ISDN");
            $this->AddType(21, "RT");
            $this->AddType(22, "NSAP");
            $this->AddType(23, "NSAP-PTR");
            $this->AddType(24, "SIG");
            $this->AddType(25, "KEY");
            $this->AddType(26, "PX");
            $this->AddType(27, "GPOS");
            $this->AddType(28, "AAAA");
            $this->AddType(29, "LOC");
            $this->AddType(31, "EID");
            $this->AddType(32, "NIMLOC");
            $this->AddType(33, "SRV");
            $this->AddType(34, "ATMA");
            $this->AddType(35, "NAPTR");
            $this->AddType(36, "KX");
            $this->AddType(37, "CERT");
            $this->AddType(39, "DNAME");
            $this->AddType(40, "SINK");
            $this->AddType(41, "OPT");
            $this->AddType(42, "APL");
            $this->AddType(43, "DS");
            $this->AddType(44, "SSHFP");
            $this->AddType(45, "IPSECKEY");
            $this->AddType(46, "RRSIG");
            $this->AddType(47, "NSEC");
            $this->AddType(48, "DNSKEY");
            $this->AddType(49, "DHCID");
            $this->AddType(50, "NSEC3");
            $this->AddType(51, "NSEC3PARAM");
            $this->AddType(52, "TLSA");
            $this->AddType(55, "HIP");
            $this->AddType(56, "NINFO");
            $this->AddType(57, "RKEY");
            $this->AddType(58, "TALINK");
            $this->AddType(59, "CDS");
            $this->AddType(99, "SPF");
            $this->AddType(249, "TKEY");
            $this->AddType(250, "TSIG");
            $this->AddType(251, "IXFR");
            $this->AddType(252, "AXFR");
            $this->AddType(253, "MAILB");
            $this->AddType(254, "MAILA");
            $this->AddType(255, "ANY");
            $this->AddType(32768, "TA");
            $this->AddType(32769, "DLV");
            $this->AddType(65534, "TYPE65534"); // Eurid uses this one?
        }

        function GetByName($name)
        {
            if (isset($this->types_by_name[$name])) {
                return $this->types_by_name[$name];
            } else {
                throw new dnsException("Invalid name $name specified on GetByName");
            }

        }

        function GetById($id)
        {
            if (isset($this->types_by_id[$id])) {
                return $this->types_by_id[$id];
            } else {
                throw new dnsException("Invalid id $id on GetById");
            }
        }
    }
}