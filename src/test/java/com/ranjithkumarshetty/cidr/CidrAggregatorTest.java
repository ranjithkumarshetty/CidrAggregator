package com.ranjithkumarshetty.cidr;

import org.apache.commons.collections.CollectionUtils;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class CidrAggregatorTest {
    @DataProvider
    public Object[][] invalidHosts() {
        List<String> hosts1 = Arrays.asList("-1.-1.-1.-1");
        List<String> hosts2 = Arrays.asList("some invalid hostname");
        List<String> hosts3 = Arrays.asList("0.0.whatif I write something here");
        List<String> hosts4 = Arrays.asList("167.1.173.32/24");
        List<String> hosts5 = Arrays.asList("abcd::efgh::ijkl::mnop");

        return new Object[][] {{hosts1}, {hosts2}, {hosts3}, {hosts4}, {hosts5}};
    }

    @Test(description = "If the hosts passed are invalid make sure CidrAggregator handles it appropriately",
                    enabled = true, dataProvider = "invalidHosts",
                    expectedExceptions = {IllegalArgumentException.class})
    public void testCidrAggregationForInvalidHosts(List<String> hosts) {
        CidrAggregator.aggregateCIDRs(hosts);
    }

    @DataProvider
    public Object[][] emptyHosts() {
        List<String> hosts1 = Collections.emptyList();
        List<String> hosts2 = null;

        return new Object[][] {{hosts1}, {hosts2}};
    }

    @Test(description = "If no hosts are passed make sure CidrAggregator handles it appropriately", enabled = true,
                    dataProvider = "emptyHosts")
    public void testEmptyHosts(List<String> hosts) {
        validateCidrAggregation(hosts, new ArrayList<String>());
    }

    @Test(description = "Test Cidr aggregation for ipv4 ip", enabled = true)
    public void testCidrAggregationForIpv4Ip() {

        validateCidrAggregation(Arrays.asList("123.123.123.123"), Arrays.asList("123.123.123.123/32"));

        validateCidrAggregation(Arrays.asList("123.123.123.123", "123.123.123.154"),
                        Arrays.asList("123.123.123.123/32", "123.123.123.154/32"));

        validateCidrAggregation(Arrays.asList("123.123.123.123", "120.123.123.123"),
                        Arrays.asList("123.123.123.123/32", "120.123.123.123/32"));

        validateCidrAggregation(Arrays.asList("255.255.255.254", "255.255.255.255"),
                        Arrays.asList("255.255.255.254/31"));

        validateCidrAggregation(Arrays.asList("255.255.255.254", "255.255.255.255", "255.255.0.2"),
                        Arrays.asList("255.255.255.254/31", "255.255.0.2/32"));
    }

    @Test(description = "Test Cidr aggregation for ipv4 netmask", enabled = true)
    public void testCidrAggregationForIpv4Netmask() {

        validateCidrAggregation(Arrays.asList("123.123.123.0/32"), Arrays.asList("123.123.123.0/32"));

        validateCidrAggregation(Arrays.asList("123.123.123.0/32", "123.123.123.0/31"),
                        Arrays.asList("123.123.123.0/31"));

        validateCidrAggregation(Arrays.asList("123.123.123.0/32", "123.123.123.130/31"),
                        Arrays.asList("123.123.123.0/32", "123.123.123.130/31"));
    }

    @Test(description = "Test Cidr aggregation for valid ipv6 ips", enabled = true)
    public void testCidrAggregationForIpv6Ip() {
        validateCidrAggregation(Arrays.asList("::0", "::0"), Arrays.asList("::/128"));
        validateCidrAggregation(Arrays.asList("::0", "::1"), Arrays.asList("::/127"));
        validateCidrAggregation(Arrays.asList("::0", "::1", "::2", "::3"), Arrays.asList("::/126"));
        validateCidrAggregation(Arrays.asList("::0", "::1", "::2", "::3", "::4", "::5", "::6", "::7"),
                        Arrays.asList("::/125"));
        validateCidrAggregation(Arrays.asList("::0", "::1", "::2"), Arrays.asList("::/127", "::2/128"));
        validateCidrAggregation(Arrays.asList("::0", "::1", "::2", "::3", "::4"), Arrays.asList("::/126", "::4/128"));
        validateCidrAggregation(Arrays.asList("::0", "::1", "::2", "::3", "::4", "::5"),
                        Arrays.asList("::/126", "::4/127"));
        validateCidrAggregation(Arrays.asList("::1", "::1"), Arrays.asList("::1/128"));
        validateCidrAggregation(Arrays.asList("::2", "::3", "::4"), Arrays.asList("::2/127", "::4/128"));
    }

    @Test(description = "Test Cidr aggregation for valid ipv6 netmasks", enabled = true)
    public void testCidrAggregationForIpv6Netmask() {
        validateCidrAggregation(Arrays.asList("::/126", "::4/128"), Arrays.asList("::/126", "::4/128"));
        Assert.assertEquals(CidrAggregator.aggregateCIDRs(Arrays.asList("::/127", "::/128")), Arrays.asList("::/127"));
        validateCidrAggregation(Arrays.asList("::/128", "::/128"), Arrays.asList("::/128"));
    }

    private void validateCidrAggregation(List<String> hosts, List<String> expectedAggregation) {
        Assert.assertTrue(CollectionUtils.isEqualCollection(CidrAggregator.aggregateCIDRs(hosts), expectedAggregation));
    }
}
