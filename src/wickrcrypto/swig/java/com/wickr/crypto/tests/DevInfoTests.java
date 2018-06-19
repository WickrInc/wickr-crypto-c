package com.wickr.crypto.tests;

import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.*;
import org.junit.Test;
import com.wickr.crypto.*;
import java.io.*;
import java.util.*;

public class DevInfoTests {
	
	@Test 
	public void testDevInfoGeneration() throws UnsupportedEncodingException
	{
		//Generate device info with a random salt using only a system identifier
		byte[] sysid = "testsysid".getBytes("UTF8");
		DeviceInfo devinfo = DeviceInfo.gen(sysid);

		assertNotNull(devinfo);

		//Compute device info from an existing salt and system identifier
		DeviceInfo devinfocompute = DeviceInfo.compute(devinfo.getDevSalt(), sysid);
		assertNotNull(devinfo);

		assertArrayEquals(devinfo.getMsgProtoId(), devinfocompute.getMsgProtoId());
		assertArrayEquals(devinfo.getSrvCommId(), devinfocompute.getSrvCommId());

		DeviceInfo anotherInfo = DeviceInfo.gen("anothersysid".getBytes("UTF8"));
		assertNotNull(anotherInfo);

		assertThat(anotherInfo.getMsgProtoId(), not(equalTo(devinfocompute.getMsgProtoId())));
		assertThat(anotherInfo.getSrvCommId(), not(equalTo(devinfocompute.getSrvCommId())));

	}

}