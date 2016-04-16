package com.ranjithkumarshetty.cidr;

import net.ripe.commons.ip.Ipv4;
import net.ripe.commons.ip.Ipv4Range;
import net.ripe.commons.ip.Ipv6;
import net.ripe.commons.ip.Ipv6Range;
import net.ripe.commons.ip.SortedResourceSet;

import org.apache.commons.collections.CollectionUtils;
import org.bouncycastle.util.IPAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;


public final class CidrAggregator {
    private static final Logger LOGGER = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private CidrAggregator() {

    }

    // Algorithm:
    // 1. Ignore host if the host is one among the placeholder subnets
    // 2. Depending on whether the host is a valid ipv4/ipv6 netmask or an ip add it to the resourceset
    // 3. aggregate each of the resourceset into cidrs and return the result
    /**
     * @param hosts List of ips to be aggregated into CIDRs
     * @return aggregated CIDRs
     */
    public static List<String> aggregateCIDRs(Set<String> hosts) {
        List<String> aggregatedCidrs = new ArrayList<String>();
        if (CollectionUtils.isEmpty(hosts)) {
            return aggregatedCidrs;
        }

        SortedResourceSet<Ipv4, Ipv4Range> ipv4ResourceSet = new SortedResourceSet<Ipv4, Ipv4Range>();
        SortedResourceSet<Ipv6, Ipv6Range> ipv6ResourceSet = new SortedResourceSet<Ipv6, Ipv6Range>();
        for (String host : hosts) {
            try {
                if (IPAddress.isValidIPv4WithNetmask(host)) {
                    ipv4ResourceSet.add(Ipv4Range.parse(host));
                } else if (IPAddress.isValidIPv4(host)) {
                    ipv4ResourceSet.add(Ipv4.of(host));
                } else if (IPAddress.isValidIPv6WithNetmask(host)) {
                    ipv6ResourceSet.add(Ipv6Range.parse(host));
                } else if (IPAddress.isValidIPv6(host)) {
                    ipv6ResourceSet.add(Ipv6.of(host));
                } else {
                    LOGGER.warn("Ignoring host:{} since it is in invalid format", host);
                }
            } catch (IllegalArgumentException ex) {
                LOGGER.warn("Ignoring host:{} since it is in invalid format", host);
            }
        }

        aggregatedCidrs.addAll(createAggregatedCidrsFromIpv4Range(ipv4ResourceSet));
        aggregatedCidrs.addAll(createAggregatedCidrsFromIpv6Range(ipv6ResourceSet));
        return aggregatedCidrs;
    }

    private static List<String> createAggregatedCidrsFromIpv6Range(SortedResourceSet<Ipv6, Ipv6Range> ipv6ResourceSet) {
        List<String> aggregatedCidrs = new ArrayList<String>();
        for (Ipv6Range ipv6Resource : ipv6ResourceSet) {
            List<Ipv6Range> ipv6Ranges = Ipv6Range.parse(ipv6Resource.toString()).splitToPrefixes();
            for (Ipv6Range ipv6Range : ipv6Ranges) {
                aggregatedCidrs.add(ipv6Range.toString());
            }
        }
        return aggregatedCidrs;

    }

    private static List<String> createAggregatedCidrsFromIpv4Range(SortedResourceSet<Ipv4, Ipv4Range> ipv4ResourceSet) {
        List<String> aggregatedCidrs = new ArrayList<String>();
        for (Ipv4Range ipv4Resource : ipv4ResourceSet) {
            List<Ipv4Range> ipv4Ranges = Ipv4Range.parse(ipv4Resource.toString()).splitToPrefixes();
            for (Ipv4Range ipv4Range : ipv4Ranges) {
                aggregatedCidrs.add(ipv4Range.toString());
            }
        }
        return aggregatedCidrs;
    }
}
