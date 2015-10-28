import java.io.UnsupportedEncodingException;


public class DnsAnswerValues 
{
	private byte[] dnsAnswer = null;
	private int beginDataIndex = 0;
	private int endDataIndex = 0;
	private int TTL = 0;
	private short TYPE = 0xff;
	private short CLASS = 0x00;
	private short RDLENGTH;
	private short PREFERENCE = 0;
	private String domainName = "";
	private String domainIp = "";
	private String record = "";

	public DnsAnswerValues(byte[] dnsAnswer, int beginDataIndex)
	{
		this.dnsAnswer = dnsAnswer;
		this.beginDataIndex = beginDataIndex;
	}

	public void ReadDnsResponse()
	{		
		int offset = beginDataIndex;
		
		// First get the domain name
		if (isPointer(dnsAnswer[offset]))
		{
			int domainNameIndex = mergeTwoBytes((byte)(dnsAnswer[offset] & 0x3F), dnsAnswer[offset + 1]);
			domainName = byteArrayToDomainName(domainNameIndex, dnsAnswer);
		}
		
		offset += 2;
		
		// is a 16-bit code specifying the meaning of the data in the RDATA field.
		TYPE = mergeTwoBytes(dnsAnswer[offset], dnsAnswer[offset + 1]);
		offset += 2;

		// is a 16-bit code with meaning similar to that of QCODE in question packets.
		CLASS = mergeTwoBytes(dnsAnswer[offset], dnsAnswer[offset + 1]);
		offset += 2;

		/*
		 * is an unsigned 32-bit integer that specifies the number of seconds that this record may be cached
		 * before it should be discarded (invalidated). If the response contains a resource record with TTL
		 * equal to zero, this should be interpreted that the response is only valid for the present query and
		 * should not be cached.
		 */
		TTL = mergeFourBytes(dnsAnswer[offset], 
							 dnsAnswer[offset + 1], 
							 dnsAnswer[offset + 2], 
							 dnsAnswer[offset + 3]);

		offset += 4;

		// is an unsigned 16-bit integer that specifies the length (in octets) of the RDATA field.
		RDLENGTH = mergeTwoBytes(dnsAnswer[offset], dnsAnswer[offset + 1]);
		offset += 2;
		
		endDataIndex = offset + RDLENGTH;

		/*
		 * a variable length sequence of octets that describes the resource. The format and meaning of
		 * these octets depends on the TYPE of the record. If TYPE is 0x0001, for an A (IP address) record,
		 * then RDATA is the IP address (four octets). If the TYPE is 0x0002, for a NS (name server) record,
		 * then this is the name of the server specified using the same format as the QNAME field. If the TYPE
		 * is 0x005, for CNAME records, then this is the name of the alias. If the type is 0x000f for MX (mail server)
		 * records, then RDATA has the format
		 */

		if (TYPE == 0x01)
		{
			for (int i = 0; i < RDLENGTH; i++)
			{
				//4 bytes
				domainIp += String.valueOf((int)(dnsAnswer[offset + i] & 0xff)) ;

				if (i < RDLENGTH - 1)
				{
					domainIp += ".";
				}
			}
		}
		
		else if (TYPE == 0x02 || TYPE == 0x05)
		{
			record = byteArrayToDomainName(offset, dnsAnswer);
		}

		else if (TYPE == 0x0f)
		{			
			PREFERENCE = mergeTwoBytes(dnsAnswer[offset], dnsAnswer[offset + 1]);
			offset += 2;
			
			// Check if we have a pointer. if we do, reset the offset.
			if (isPointer(dnsAnswer[offset]))
			{								
				offset = mergeTwoBytes((byte)(dnsAnswer[offset] & 0x3f), dnsAnswer[offset + 1]);
			}

			record = byteArrayToDomainName(offset, dnsAnswer);
		}

		else
		{
			System.out.println("ERROR \t Reponse type " + '"' + numberToHexString((int)(TYPE & 0xff), "0x%2s") + '"' + " not supported.");
		}
	}
	
	public static String byteArrayToDomainName(int offset, byte[] array)
	{
		String str = "";
		
		if (isPointer(array[offset]))
		{
			offset = mergeTwoBytes((byte)(array[offset] & 0x3F), array[offset + 1]);
		}
		
		int labelLength = array[offset];
		byte[] character = new byte[1];

		offset++;
		while (labelLength != 0)
		{
			// Append the label characters into one string.
			for (int i = 0; i < labelLength; i++)
			{
				character[0] = array[offset + i];
				try
				{
					str += new String(character, "US-ASCII");
				}
				catch (UnsupportedEncodingException e) 
				{
					System.out.println("ERROR \t Unable to convert bytes to unicode.");
				} 
			}

			// Update the array index by increasing it by one. Then check if we have a pointer or not
			offset += labelLength;
			if (isPointer(array[offset]))
			{							
				offset = mergeTwoBytes((byte)(array[offset] & 0x3f), array[offset + 1]);
			}

			// Get the next label
			labelLength = array[offset];
			offset++;

			if (labelLength != 0)
			{
				// Append the "." the the string.
				str += ".";
			}
		}
		
		return str;
	}
	
	public static short mergeTwoBytes(byte left, byte right)
	{
		short value = (short) (left & 0xff);
		value = (short)(value << 8);
		
		return (short)(value | (right & 0xff));
	}

	public static int mergeFourBytes(byte one, byte two, byte three, byte four)
	{
		int value = (one & 0xff);
		value = value << 8;

		value = value | (two & 0xff);
		value = value << 8;

		value  = value | (three & 0xff);
		value = value << 8;

		value = value | (four & 0xff);

		return value;
	}
	
	public static boolean isPointer(byte value)
	{
		return ((value & 0xc0) == 0xc0);
	}
	
	public static String numberToHexString(int n, String format) 
	{
	    return String.format(format, Integer.toHexString(n)).replace(' ', '0');
	}

	public int getBeginDataIndex() 
	{
		return beginDataIndex;
	}

	public int getEndDataIndex() 
	{
		return endDataIndex;
	}

	public int getTTL() 
	{
		return TTL;
	}

	public short getTYPE()
	{
		return TYPE;
	}

	public short getCLASS() 
	{
		return CLASS;
	}

	public short getRDLENGTH() 
	{
		return RDLENGTH;
	}

	public short getPREFERENCE() 
	{
		return PREFERENCE;
	}
	
	public String getTypeAsString()
	{
		String type = "";
		
		if (TYPE == 0x01)
		{
			type = "A";
		}
		
		else if (TYPE == 0x02)
		{
			type = "NS";
		}
		
		else if (TYPE == 0x05)
		{
			type = "CNAME";
		}
		
		else if (TYPE == 0x0f)
		{
			type = "MX";
		}
		
		return type;
	}

	public String getDomainName() 
	{
		return domainName;
	}

	public String getDomainIp() 
	{
		return domainIp;
	}

	public String getMxRecord()
	{
		return record;
	}	
}
