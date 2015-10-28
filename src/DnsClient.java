import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.Random;

// http://www.t1shopper.com/tools/nslookup/result/
// 132.206.85.18 mcgill 
// 208.109.255.26 stackoverflow.com no recursive
// 132.204.8.207 mcgill.ca is auth
/**
 * Hello
 * @author mac
 *
 */
public class DnsClient
{
	static int timeOut = 5;
	static int maxRetries = 3;
	static int numberOfRetries = 0;
	static int port = 53;
	static int numberOfAnswers = 0;
	static int numberOfAdditionalRecords = 0;
	static double responseTime = 0;
	static boolean useAA = true;
	static boolean useMx = false;
	static boolean useNs = false;
	static String serverIp = "";
	static String domainName = "";
	static String authOrNot = "";
	static byte[] ip = new byte[4];
	static byte[] dnsAnswer = null;
	static DnsAnswerValues[] dnsAdditionalInformation = null;
	static DnsAnswerValues[] answerValues = null;
	
	final static int HEADER_BUFFER_SIZE = 12; 

	public static void main(String[] args) throws Exception
	{
		if (!simpleCommandLineArgParser(args))
		{
			return;
		}

		byte[] header = createDnsHeader();
		byte[] dnsQuestion = createDnsQuestion();
		
		if(dnsQuestion == null)
		{
			return;
		}
		
		byte[] dnsRequest = createRequest(header, dnsQuestion);
		dnsAnswer = dnsLookup(dnsRequest);	
		
		if (dnsAnswer == null)
		{
			System.out.println("ERROR \t Maximum number of retries " + '"' + (numberOfRetries - 1) + '"' + " exceeded.");
			
			return;
		}
		
		boolean success = readDnsAnswer(dnsQuestion.length);
		
		if (success)
		{
			printResults();
		}
	}

	public static boolean simpleCommandLineArgParser(String[] args)
	{
		if (args.length < 2)
		{
			System.out.println("ERROR \t Invalid program syntax.\nUse: [-t timeout] [-r max-retires] [-p port] [mx | ns] @server name");
			return false;
		}

		int index = 0;
		while (index < args.length - 2)
		{
			if (args[index].equalsIgnoreCase("-t"))
			{
				if (args.length > index + 1)
				{
					try
					{
						timeOut = getParameterValue(args[index], args[index +1]);
						
						if (timeOut < 1)
						{
							System.out.println("ERROR \t Invalid value for parameter -t. Timeout must be greater than 0.");
							
							return false;
						}
						
						index += 2;
					}
					catch (NumberFormatException exception)
					{
						return false;
					}
				}
				else
				{
					System.out.println("ERROR \t Missing value for parameter " + '"' + args[index] + '"');
					
					return false;
				}
			}

			else if (args[index].equalsIgnoreCase("-r"))
			{
				if (args.length > index + 1)
				{
					try
					{
						maxRetries = getParameterValue(args[index], args[index +1]);
						
						if (maxRetries < 0)
						{
							System.out.println("ERROR \t Invalid value for parameter -r. Maximum number of retries must be greater or equal to 0.");
							
							return false;
						}
						
						index += 2;
					}
					catch (NumberFormatException exception)
					{
						return false;
					}
				}
				else
				{
					System.out.println("ERROR \t Missing value for parameter " + '"' + args[index] + '"');
					
					return false;
				}
			}

			else if (args[index].equalsIgnoreCase("-p"))
			{
				if (args.length > index + 1)
				{
					try
					{
						port = getParameterValue(args[index], args[index +1]);
						
						if (port < 0)
						{
							System.out.println("ERROR \t Invalid value for parameter -p. Port number must be greater or equal to 0.");
							
							return false;
						}
						
						index += 2;
					}
					catch (NumberFormatException exception)
					{
						return false;
					}
				}
				else
				{
					System.out.println("ERROR \t Missing value for parameter " + '"' + args[index] + '"');
					return false;
				}
			}

			else if (args[index].equalsIgnoreCase("-mx"))
			{
				useMx = true;
				index++;
			}

			else if (args[index].equalsIgnoreCase("-ns"))
			{
				useNs = true;
				index++;
			}

			
			// Make sure that the user did not pass any invalid parameter.
			if (index < (args.length - 2)	         &&
				!args[index].equalsIgnoreCase("-p")  && 
				!args[index].equalsIgnoreCase("-r")  && 
				!args[index].equalsIgnoreCase("-t")  && 
				!args[index].equalsIgnoreCase("-ns") &&
				!args[index].equalsIgnoreCase("-mx"))
			{
				System.out.println("ERROR \t " + '"' + args[index] + '"' + " Is not a valid parameter.");
				
				return false;
			}
		}
		
		// Check the syntax for the IP server
		if (index == (args.length - 2) && !args[args.length - 2].startsWith("@"))
		{
			System.out.println("ERROR \t Invalid syntax for server IP. Use @xx.xx.xx.xx");
			
			return false;
		}

		if (useMx && useNs)
		{
			System.out.println("ERROR \t Mail Server(mx) and Name Server(ns) cannot be enabled at the same time.");
			
			return false;
		}
		else if (useMx || useNs)
		{
			useAA = false;
		}

		domainName = args[args.length - 1];

		return parseIpAddress(args[args.length - 2]);
	}

	public static int getParameterValue(String parameter, String value) 
	{
		int number = 0;
		try 
		{
			number = Integer.parseInt(value);
		}
		
		catch (NumberFormatException exception)
		{	
			System.out.println("ERROR \t Invalid value for parameter " + parameter + ". " + value + " is not an integer.");
			throw exception;
		}

		return number;
	}

	public static boolean parseIpAddress(String ipString)
	{
		if (ipString.startsWith("@"))
		{
			ipString = ipString.substring(1);
		}

		// Save the server IP address.
		serverIp = ipString;
		
		// Parse the IP and store it into a byte array
		String[] ipParts = ipString.split("\\.");
		for (int i = 0; i < ip.length; i++)
		{
			try 
			{
				int value = Integer.parseInt(ipParts[i]);

				if (value > 255)
				{
					System.out.println("ERROR \t IP values cannot be larger than 255");
					return false;
				}

				ip[i] = (byte)value;
			}
			catch (NumberFormatException exception)
			{	
				System.out.println("ERROR \t invalid IP address " + '"' + ipParts[i] + '"' + " is not a number.");
			}
		}

		return true;
	}

	public static byte[] dnsLookup(byte[] dnsRequest) throws Exception
	{
		// Create a UDP socket
		DatagramSocket clientSocket = new DatagramSocket();
		
		// Set the timeout for the socket.
		clientSocket.setSoTimeout(timeOut * 1000);

		// Resolve a domain name to an IP address object
		//byte[] serverIpAddress = {(byte)132, (byte)206, (byte)85, (byte)18};
		InetAddress ipAddress = InetAddress.getByAddress(ip);

		// Allocate buffers for the data to be received	
		// TODO: what should be the buffer size????????
		byte[] receiveData = new byte[1024];

		// Create a UDP packet to be sent to the server
		DatagramPacket sendPacket = new DatagramPacket(dnsRequest, dnsRequest.length, ipAddress, port);
		
		// Send the packet
		clientSocket.send(sendPacket);

		// Create a packet structure to store data sent back by the server
		DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);

		byte[] answer = null;
		boolean gotResponse = false;
		
		// measure the time required to get an answer. 
		long start_time = System.nanoTime();
		while (numberOfRetries <= maxRetries && !gotResponse)
		{
			try 
			{
				// Receive data from the server
				clientSocket.receive(receivePacket);
				gotResponse = true;
			}
			catch (SocketTimeoutException exception)
			{
				numberOfRetries++;
				answer = null;
				gotResponse = false;
			}
		}
		
		long end_time = System.nanoTime();
		responseTime = (end_time - start_time) / 1e9;
		
		if (gotResponse)
		{
			// Extract the answer
			answer = receivePacket.getData();
		}

		// Close the socket
		clientSocket.close();

		return answer;
	}

	public static byte[] createRequest(byte[] header, byte[] dnsQuestion)
	{
		byte[] dnsRequest = new byte[header.length + dnsQuestion.length];

		for( int i = 0 ; i < header.length ; i++ )
		{
			dnsRequest[i] = header[i];
		}
		
		for( int i = 0 ; i < dnsQuestion.length ; i++ )
		{
			dnsRequest[header.length + i] = dnsQuestion[i];
		}

		return dnsRequest;
	}

	public static byte[] createDnsHeader()
	{
		byte[] header = new byte[HEADER_BUFFER_SIZE];

		// create a random ID for the header.
		Random randomGenerator = new Random();
		byte randomIdLeft = (byte)randomGenerator.nextInt(255);
		byte randomIdRight = (byte)randomGenerator.nextInt(255);

		// Append the two random ID to make a 16-bit ID.
		header[0] = randomIdLeft;
		header[1] = randomIdRight;
		
		// is 1 because QR, Opcode, AA, TC are all zeros except the last bit which is RD = 1
		header[2] = 1;
		
		// ra to rcode are all 0
		header[3] = 0;
		
		// qdcount is number of entries in the question section which is equal to 1
		header[4] = 0;
		header[5] = 1;
		
		// ancount is the answer given by server
		header[6] = 0;
		header[7] = 0;

		// nscount our program can ignore
		header[8] = 0;
		header[9] = 0;

		// arcount resource records in the additional records section
		header[10] = 0;
		header[11] = 0;

		return header;
	}

	public static byte[] createDnsQuestion()
	{
		String[] domainSplit = domainName.split("\\.");
		byte[] qname = null;
		
		//Check if each label is valid i.e. label width <= octect
		for(int i = 0 ; i < domainSplit.length ; i++)
		{
			if(domainSplit[i].length() > 63)
			{
				System.out.println("ERROR \t One of the domain label needs to be less than 63 octects");
				
				return null;
			}
		}

		// QNAME
		int totalCharactersCount = 0;
		for (int i = 0; i < domainSplit.length; i++)
		{
			totalCharactersCount += domainSplit[i].length();		
		}
		
		// Total number of character + number of labels + 1 zero at the end.
		qname = new byte[totalCharactersCount + domainSplit.length + 1];

		// fill the byte array with values
		int count = 0;
		for (int i = 0; i < domainSplit.length; i++)
		{ 
			qname[count] = (byte)domainSplit[i].length();
			count++;
			
			for( int j = 0 ; j < domainSplit[i].length() ; j++)
			{
				qname[count] = (byte)domainSplit[i].charAt(j);
				count++;
			}
		}
		
		// Append 0 
		qname[qname.length - 1] = 0;

		// QTYPE is by default 0x0001
		byte qtypeLeft = 0x00;
		byte qTypeRight = 0x01;
		
		// Set the right QTYPE if -mx or -ns was set.
		if (useMx)
		{
			qTypeRight = 0x0f;
		}
		
		else if (useNs)
		{
			qTypeRight = 0X02;
		}
		
		//QCLASS always 1 and is the class of the query
		byte qclassLeft = 0x00;
		byte qclassRight = 0x01;

		//dnsQuestion -> length = qname + 2 for qtype and 2 for qclass
		byte[] dnsQuestion = new byte[qname.length + 4];

		// Fill the DNS question
		for(int i = 0 ; i < qname.length ; i++)
		{
			dnsQuestion[i] = qname[i];
		}

		dnsQuestion[dnsQuestion.length - 1] = qclassRight;
		dnsQuestion[dnsQuestion.length - 2] = qclassLeft;
		dnsQuestion[dnsQuestion.length - 3] = qTypeRight;
		dnsQuestion[dnsQuestion.length - 4] = qtypeLeft;

		return dnsQuestion;
	}

	public static boolean readDnsAnswer(int dnsQuestionLength)
	{
		// TODO: do we need to check if the message is a response or not???

		// Get the header from the answer.
		byte[] header = new byte[HEADER_BUFFER_SIZE];
		for (int i = 0; i < HEADER_BUFFER_SIZE; i++)
		{
			header[i] = dnsAnswer[i];
		}
		
		// Check if the server is authority or not. The AA flag corresponds to the 22-bit in the header
		// mask the 3rd bit which corresponds to the AA flag
		byte authority = (byte)(header[2] & 0x04);
		
		if ((authority & 0xff) == 0x04)
		{
			authOrNot = "auth";
		}
		else
		{
			authOrNot = "nonauth";
		}
		
		// Check if the server supports recursive queries.
		// Mask the MSB bit which corresponds to RA flag.
		byte supportRecursiveQueries = (byte)(header[3] & 0x80);
		if ((supportRecursiveQueries & 0xff) != 0x80)
		{
			System.out.println("ERROR \t Server does not support recursive queries.");
			
			return false;
		}
		
		// Check the RCODE and report if there is an error.
		// Mask the last four bits
		byte RCODE = (byte)(header[3] & 0x0f);
		if ((RCODE & 0xff) != 0x00)
		{
			if ((RCODE & 0xff) == 0x01)
			{
				System.out.println("ERROR \t Format error: the name server was unable to interpret the query.");
			}
			
			else if ((RCODE & 0xff) == 0x02)
			{
				System.out.println("ERROR \t Server failure: the name server was unable to process this query due to a problem with the name server.");
			}
			
			else if ((RCODE & 0xff) == 0x03)
			{
				System.out.println("NOTFOUND");
			}
			
			else if ((RCODE & 0xff) == 0x04)
			{
				System.out.println("ERROR \t Not implemented: the name server does not support the requested kind of query.");
			}
			
			else if ((RCODE & 0xff) == 0x05)
			{
				System.out.println("ERROR \t Refused: the name server refuses to perform the requested operation for policy reasons.");
			}
			
			return false;
		}
		
		// Store the number of answers. Index 6 and 7 of the header contains this value
		numberOfAnswers = DnsAnswerValues.mergeTwoBytes(header[6], header[7]);
		
		// Check if there is any record in the additional section.
		numberOfAdditionalRecords = DnsAnswerValues.mergeTwoBytes(header[10], header[11]);
	
		// Don't do anything if we don't get any answer
		if (numberOfAnswers == 0)
		{
			System.out.println("NOTFOUND");
			
			return false;
		}
		
		int answerIndex = HEADER_BUFFER_SIZE + dnsQuestionLength;
		answerValues = new DnsAnswerValues[numberOfAnswers];

		for (int i = 0; i < answerValues.length; i++)
		{
			answerValues[i] = new DnsAnswerValues(dnsAnswer, answerIndex);
			answerValues[i].ReadDnsResponse();
			
			answerIndex = answerValues[i].getEndDataIndex();
		}
		
		if (numberOfAdditionalRecords > 0)
		{
			dnsAdditionalInformation = new DnsAnswerValues[numberOfAdditionalRecords];
			answerIndex = answerValues[answerValues.length - 1].getEndDataIndex();

			for (int i = 0; i < dnsAdditionalInformation.length; i++)
			{
				dnsAdditionalInformation[i] = new DnsAnswerValues(dnsAnswer, answerIndex);
				dnsAdditionalInformation[i].ReadDnsResponse();
				
				answerIndex = dnsAdditionalInformation[i].getEndDataIndex();
			}
		}
		
		return true;
	}
	
	public static void printResults()
	{
		System.out.println("DnsClient sending request for " + domainName);
		System.out.println("Server: " + serverIp);
		System.out.println("Resquest type: " + getRequestType());
		System.out.printf("Reponse received after %.8f seconds (%d retries)\n", responseTime, numberOfRetries);
		
		if (answerValues != null)
		{
			System.out.println("\n***Answer Section  (" + numberOfAnswers + " records)***");
			for (int i = 0; i < answerValues.length; i++)
			{
				printFormattedAnswer(answerValues[i]);
			}
		}
		
		if (numberOfAdditionalRecords > 0)
		{
			System.out.println("\n***Additional Section (" + numberOfAdditionalRecords + " records)***");
			for (int i = 0; i < dnsAdditionalInformation.length; i++)
			{
				printFormattedAnswer(dnsAdditionalInformation[i]);
			}
		}
	}
	
	public static void printFormattedAnswer(DnsAnswerValues answer)
	{
		if (answer.getTYPE() == 0x01)
		{
			System.out.println("IP \t " + answer.getDomainIp() + " \t " + answer.getTTL() + " seconds can cache \t " + authOrNot);
		}
		
		else if (answer.getTYPE() == 0x02 || answer.getTYPE() == 0x05)
		{
			System.out.println(answer.getTypeAsString() + " \t " + answer.getMxRecord() + " \t " + answer.getTTL() + " seconds can cache\t" + authOrNot );
		}
		
		else if (answer.getTYPE() == 0x0f)
		{
			System.out.println(answer.getTypeAsString() + " \t " + answer.getMxRecord() + " \t " + answer.getPREFERENCE() + " \t " + answer.getTTL() + " seconds can cache \t" + authOrNot );
		}
		
		else 
		{
			System.out.println("ERROR \t Reponse type " + '"' + DnsAnswerValues.numberToHexString((int)(answer.getTYPE() & 0xff), "0x%2s") + '"' + " not supported.");
		}
	}
	
	public static String getRequestType()
	{
		String type = "";
		
		if (useAA)
		{
			type = "A";
		}
		
		else if (useMx)
		{
			type = "MX";
		}
		
		else if (useNs)
		{
			type = "NS";
		}
		
		return type;
	}
	
	public static void debugPrintByteArray(byte[] array, int startIndex, int endIndex, String label)
	{
		if (startIndex >= endIndex)
		{
			System.out.println("ERROR: invalid range");
		}
		
		else if (startIndex < 0 || startIndex >= array.length)
		{
			System.out.println("ERROR: Invalid start index");
		}
		
		else if (endIndex < 1 || endIndex > array.length)
		{
			System.out.println("ERROR: Invalid end index");
		}
		
		else
		{
			System.out.println("=========== " + label + " ===========");
			for(int i = startIndex; i < endIndex; i++)
			{
				System.out.println(DnsAnswerValues.numberToHexString((int)(array[i] & 0xff), "0x%2s"));
			}
			System.out.println("");
		}
	}
}
