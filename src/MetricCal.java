import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.StringTokenizer;

class RouterInfo {
	ArrayList<Integer> openports;
	ArrayList<String> OS;
	Double Bandwidth;

	public RouterInfo() {
		openports = new ArrayList<Integer>();
		OS = new ArrayList<String>();
		Bandwidth = 0.0;

	}

	public RouterInfo(ArrayList<Integer> ports, ArrayList<String> os) {
		openports = ports;
		OS = os;
		Bandwidth = 1.0;

	}

	public void setrinfo(ArrayList<Integer> ports, ArrayList<String> os) {
		openports = ports;
		OS = os;

	}
}

class Parser {

	HashMap<String, RouterInfo> PortInfo = new HashMap<String, RouterInfo>();
	HashMap<Integer, String> HopInfo = new HashMap<Integer, String>();
	int hopcount;

	public void parsing(String filename) throws IOException {
		Integer hopno = 1;

		String file = "/home/praveen/Desktop/Research/" + filename + ".txt";

		FileReader fstream = new FileReader(file);

		BufferedReader br = new BufferedReader(fstream);

		ArrayList<Integer> ports = new ArrayList<Integer>();
		ArrayList<String> os = new ArrayList<String>();
		String readline;

		readline = br.readLine();
		Boolean Flag = false;

		while (readline != null) {
			String Router = null;
			if (readline.contains("Nmap scan")) {
				String[] stringarray = readline.split(" ");

				String routerip = stringarray[stringarray.length - 1];
				if (!routerip.contains(".0")) {
					if (routerip.startsWith("(")) {
						routerip = routerip.substring(1, routerip.length() - 1);
					} else {
						routerip = routerip.substring(0, routerip.length());
					}

					Router = routerip;
					HopInfo.put(hopno, Router);
					hopno++;
					/*
					 * readline = br.readLine(); readline = br.readLine();
					 * readline = br.readLine();
					 */

					while (!readline.contains("/")) {
						readline = br.readLine();
					}
					while (readline.contains("/")) {
						Flag = true;

						String port = readline.split("/")[0];

						ports.add(Integer.parseInt(port));
						readline = br.readLine();
						if (readline.contains("/html")) {
							readline = br.readLine();

						}
					}
					while (!readline.contains("Device type")
							&& !readline.contains("No exact"))
						readline = br.readLine();

					if (readline.contains("Device type")) {

						readline = br.readLine();

						if (readline.contains("Running")) {
							String os_temp = readline.split(":")[1];

							String[] os_fin = os_temp.split(",");
							for (String string : os_fin) {
								os.add(string);
							}
						}
					}
					if (readline.contains("No exact")) {
						os.add("empty");
					}

				}
				if (Flag) {
					RouterInfo temp = PortInfo.get(Router);
					if (temp != null)
						temp.setrinfo(ports, os);
					Flag = false;
				}
			}

			ports = new ArrayList<Integer>();
			os = new ArrayList<String>();
			readline = br.readLine();

		}
		br.close();
	}

	public void PathParsing() throws IOException {

		FileReader fstream = new FileReader(
				"/home/praveen/Desktop/Research/pathneck-output.txt");

		BufferedReader br = new BufferedReader(fstream);

		String readline = br.readLine();

		while (!readline.contains("RTT")) {
			String newreadline = readline.trim();
			String[] data = newreadline.split("\\s+");
			RouterInfo rinfo = PortInfo.get(data[0]);
			if (rinfo != null)
				rinfo.Bandwidth = Double.parseDouble(data[3]);
			readline = br.readLine();
		}
		br.close();

	}

	public void traceParsing(String filename) throws IOException {
		String file = "/home/praveen/Desktop/Research/" + filename
				+ "-tracert.txt";
		FileReader fstream = new FileReader(file);

		BufferedReader br = new BufferedReader(fstream);

		String readline = br.readLine().trim();
		ArrayList<String> intermediaterouters = new ArrayList<String>();

		while (!readline.contains("end")) {
			if (readline.contains(",")) {
				intermediaterouters.add(readline.substring(0,
						readline.length() - 1));

			} else {
				intermediaterouters.add(readline);
			}
			readline = br.readLine().trim();
		}

		hopcount = intermediaterouters.size();
		int hopno = 1;
		for (String routerip : intermediaterouters) {

			RouterInfo rinfo = new RouterInfo();
			PortInfo.put(routerip, rinfo);
			HopInfo.put(hopno, routerip);
			hopno++;

		}
		br.close();

	}

	public void tostring() {

		for (String router : PortInfo.keySet()) {

			System.out.print(router + "    ");
			RouterInfo print = PortInfo.get(router);
			ArrayList<Integer> port = print.openports;
			ArrayList<String> os_print = print.OS;
			System.out.println(port.toString());
			System.out.println(os_print.toString());
			System.out.println(print.Bandwidth);

		}

		for (Integer hopno : HopInfo.keySet()) {

			System.out.println(hopno + "   " + HopInfo.get(hopno));

		}

	}
}

/**
 * 
 * The command line format
 * 
 * 
 * 
 * @author Praveen
 * 
 *         secure : list of ports which are considered secure semisecure : list
 *         of ports which are insecure insecure : list of ports which are most
 *         vulnerable security : the list of security value of each router in
 *         the path [port vulnerability] vulnerability : list of vulnerability
 *         value of each router in the path [ OS vulnerability] destinations :
 *         lists of the routes to be examined alpha : the contribution of
 *         security value in the computation of overall security rating of route
 *         [0=<alpha<=1]
 */

public class MetricCal {

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		final int maxLen = 40;
		StringBuilder builder = new StringBuilder();
		// builder.append("");
		if (Pathportmetric != null) {
			// builder.append("Pathportmetric=");
			builder.append(Pathportmetric.subList(0,
					Math.min(Pathportmetric.size(), maxLen)));
			builder.append(":");
		}
		if (vulnerablity != null) {
			// builder.append("vulnerablity=");
			builder.append(vulnerablity.subList(0,
					Math.min(vulnerablity.size(), maxLen)));
			builder.append(":");
		}
		if (bandwidth != null) {
			// builder.append("bandwidth=");
			builder.append(bandwidth.subList(0,
					Math.min(bandwidth.size(), maxLen)));
			builder.append(":");
		}
		if (destination != null) {
			// builder.append("destination=");
			builder.append(destination);
			builder.append(":");
		}
		if (source != null) {
			// builder.append("source=");
			builder.append(source);
		}
		// builder.append("]");
		return builder.toString();
	}

	static LinkedList<Integer> insecure = new LinkedList<Integer>();
	static LinkedList<Integer> semisecure = new LinkedList<Integer>();
	static LinkedList<Integer> secure = new LinkedList<Integer>();
	ArrayList<Integer> Pathportmetric = new ArrayList<Integer>();
	ArrayList<Double> vulnerablity = new ArrayList<Double>();
	ArrayList<Double> bandwidth = new ArrayList<Double>();
	double alpha;
	String destination;
	String source;
	String fileprefix;

	/**
	 * 
	 * @param port
	 *            search port list to find the security level of the port
	 * @return the security level
	 */

	static public int securityvalue(int port) {

		int secvalue = 10;

		if (insecure.contains(port))
			secvalue = 10;

		if (semisecure.contains(port))
			secvalue = 5;

		if (secure.contains(port))
			secvalue = 0;

		return secvalue;
	}

	static public Double vulnerabilityvalue(String searchos)
			throws SQLException, InstantiationException,
			IllegalAccessException, ClassNotFoundException {

		// connect to database

		String dbUrl = "jdbc:mysql://localhost:3306/";
		String dbname = "test1";
		Class.forName("com.mysql.jdbc.Driver").newInstance();
		Connection con = DriverManager.getConnection(dbUrl + dbname, "root",
				"root");

		// Perform a lookup and arrange in descending order :
		// take the max value

		String query = " SELECT score FROM `vulindex` WHERE product LIKE "
				+ "\"%" + searchos + "%" + "\"" + " ORDER BY score DESC";
		System.out.println(query);
		PreparedStatement stmt = con.prepareStatement(query);
		ResultSet rs = stmt.executeQuery();

		// check if there is an entry in the result set after
		// search

		if (rs.first()) {
			String t = rs.getString(1);
			return Double.parseDouble(t);

		} else {

			return 10.0;
		}

	}

	/**
	 * Function to compute the security value of each router in the path and
	 * generate a list
	 * 
	 * @return a Link List of security value for each hop in the route path
	 */

	public void Security(Parser Parse)

	{

		for (int i = 1; i <= Parse.hopcount; i++) {

			RouterInfo rinfo = Parse.PortInfo.get(Parse.HopInfo.get(i));

			int portmetric = 10;
			if (rinfo != null) {
				for (Integer port : rinfo.openports) {
					int value = securityvalue(port);

					if (value < portmetric) {
						portmetric = value;

					}

				}
			}

			Pathportmetric.add(portmetric);

		}

		for (Integer integer : Pathportmetric) {
			System.out.print(integer + " ");
		}

	}

	/**
	 * Function to compute the vulnerability value of each router in the path
	 * and generate a list
	 * 
	 * @return a Link List of vulnerability value for each hop in the route path
	 * @throws ClassNotFoundException
	 * @throws IllegalAccessException
	 * @throws InstantiationException
	 * @throws SQLException
	 */

	public void Vulnerability(Parser Parse) throws SQLException,
			InstantiationException, IllegalAccessException,
			ClassNotFoundException

	{

		for (int i = 1; i <= Parse.hopcount; i++) {

			RouterInfo rinfo = Parse.PortInfo.get(Parse.HopInfo.get(i));

			double vulmetric = 10.0;
			if (rinfo != null) {
				for (String oslist : rinfo.OS) {

					String os;
					if (oslist.contains("(")) {
						os = oslist.substring(0, oslist.length() - 5);
					}

					else
						os = oslist;

					// create a string which can be used to look up OS in
					// NIST database

					String searchos = os.replace(" ", "%").replace("X", "%")
							.replace(".", "%");

					double value = vulnerabilityvalue(searchos);
					System.out.println(value);
					if (value < vulmetric) {
						vulmetric = value;

					}
				}
			}

			vulnerablity.add(vulmetric);
		}
		System.out.println();
		System.out.print(" vulnerability: ");
		for (Double os : vulnerablity) {

			System.out.print(os + " ");
		}
	}

	public void bandwidth(Parser parse) {
		for (int i = 1; i <= parse.hopcount; i++) {

			RouterInfo rinfo = parse.PortInfo.get(parse.HopInfo.get(i));
			if (rinfo != null)
				bandwidth.add(rinfo.Bandwidth);
		}
		System.out.println();
		System.out.print("bandwidth :");
		for (double band : bandwidth) {
			System.out.print(band + " ");
		}
	}

	/**
	 * Function to insert the data collected into the database ;
	 * 
	 * @throws SQLException
	 * @throws InstantiationException
	 * @throws IllegalAccessException
	 * @throws ClassNotFoundException
	 */

	public void insertdata() throws SQLException, InstantiationException,
			IllegalAccessException, ClassNotFoundException {
		String dbUrl = "jdbc:mysql://localhost:3306/";
		String dbname = "security";

		Class.forName("com.mysql.jdbc.Driver").newInstance();
		Connection con = DriverManager
				.getConnection(dbUrl + dbname, "root", "");
		System.out.println("Connected to the database");
		// to insert security value list with source and destination ;

		StringBuilder querybuilder = new StringBuilder();

		String temp, metricstring;
		String[] insert_data = new String[4];
		temp = "INSERT INTO routedata VALUES(";

		querybuilder.append(temp);

		metricstring = this.toString().replaceAll(",", "-");
		String[] data = metricstring.split(":");

		for (int i = 0; i < data.length; i++) {
			if (data[i].contains("["))
				insert_data[i] = data[i].substring(1, data[i].length() - 1);
			else
				insert_data[i] = data[i];
		}

		querybuilder.append("\"" + source + "\"" + ",");
		querybuilder.append("\"" + destination + "\"" + ",");
		for (int insert : Pathportmetric) {
			querybuilder.append(insert);
			querybuilder.append(",");
		}
		int size = Pathportmetric.size();

		int diff = 20 - size;
		while (diff != 0) {
			querybuilder.append("-1,");
			diff--;
		}
		String query = querybuilder.substring(0, querybuilder.length() - 1)
				+ ");";

		System.out.println(query);
		PreparedStatement stmt = con.prepareStatement(query);

		if (stmt.execute()) {
			System.out.println(" database complete");
		}

		// insert vulnerability value list :
		StringBuilder querybuilder1 = new StringBuilder();

		temp = "INSERT INTO vulnerabilityindex VALUES(";

		querybuilder1.append(temp);

		querybuilder1.append("\"" + source + "\"" + ",");
		querybuilder1.append("\"" + destination + "\"" + ",");

		for (double insert : vulnerablity) {
			querybuilder1.append(insert);
			querybuilder1.append(",");
		}
		size = vulnerablity.size();

		diff = 20 - size;
		while (diff != 0) {

			// add -1 in case of fewer than 20 hops ;
			querybuilder1.append("-1,");
			diff--;
		}
		query = querybuilder1.substring(0, querybuilder1.length() - 1) + ");";

		System.out.println(query);
		stmt = con.prepareStatement(query);

		if (stmt.execute()) {
			System.out.println(" database complete");
		}

		con.close();

	}

	/**
	 * Method to compute security value of a path
	 * 
	 * @param source
	 *            source of connection from cloud [ Server IP]
	 * @param Destination
	 *            client IP
	 * @return
	 * @throws InstantiationException
	 * @throws IllegalAccessException
	 * @throws ClassNotFoundException
	 * @throws SQLException
	 * @throws InterruptedException
	 */
	public double compute(String source, String Destination)
			throws InstantiationException, IllegalAccessException,
			ClassNotFoundException, SQLException, InterruptedException {

		String dbUrl = "jdbc:mysql://localhost:3306/";
		String dbname = "security";

		Class.forName("com.mysql.jdbc.Driver").newInstance();
		Connection con = DriverManager
				.getConnection(dbUrl + dbname, "root", "");
		System.out.println("Connected to the database");

		// query to extract security value;

		String query = " select * from  securityindex where source=\"" + source
				+ "\" and destination=\"" + Destination + "\"";
		System.out.println(query);

		// compute port security parameter

		PreparedStatement stmt = con.prepareStatement(query);

		ResultSet rs = stmt.executeQuery();
		int portsecurity = 5; // default value
		int columnIndex = 0;

		System.out.println(rs.first());

		for (int k = 2; k < 20; k++) {

			int local = rs.getInt(k);
			if (portsecurity > local && local != -1) {
				portsecurity = local;
			}
			columnIndex++;

		}

		// query to find vulnerability list for a source destination pair

		query = " select * from  vulnerabilityindex where source=\"" + source
				+ "\" and destination=\"" + Destination + "\"";

		// compute OS security parameter
		stmt = con.prepareStatement(query);
		rs = stmt.executeQuery();
		int vulnerability = 0;
		// columnIndex = 2;
		System.out.println(rs.toString());
		;

		System.out.println(rs.first());

		for (int k = 2; k < 4; k++) {
			int local = rs.getInt(k);
			if (portsecurity < local) {
				vulnerability = local;
			}

		}

		// the security level decides the port value : synchronise the range of
		// sec value
		// in 1 to 10 as vulnerability in NIST is in the same range

		// double securityparameter = alpha * portvalue + (1 - alpha)
		// * vulnerability;
		// return securityparameter;
		return 0;
	}

	/**
	 * 
	 * Function to exevute the perl script
	 * 
	 * @param src
	 * @param dest
	 * @throws InterruptedException
	 * @throws IOException
	 */
	public void Execute() throws InterruptedException, IOException {

		String command = "" + " " + destination + " " + fileprefix;

		String[] params = new String[4];

		params[0] = "/usr/bin/perl";
		params[1] = "/home/praveen/Desktop/Research/tracedmp.pl";
		params[2] = destination;
		params[3] = fileprefix;
		final Process p = Runtime.getRuntime().exec(params);
		Thread thread = new Thread() {
			@Override
			public void run() {
				String line, line2 = null;
				BufferedReader input = new BufferedReader(
						new InputStreamReader(p.getInputStream()));
				BufferedReader error = new BufferedReader(
						new InputStreamReader(p.getErrorStream()));
				try {
					while ((line = input.readLine()) != null
							|| (line2 = error.readLine()) != null)
						System.out.println(line + line2);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				try {
					input.close();
					error.close();
					notifyAll();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}

		};
		thread.start();

		int result = p.waitFor();

		System.out.println("result" + result);
		if (result != 0) {
			System.out.println("Process f" + "ailed with status: " + result);
		}

	}

	/**
	 * Function to parse all the values provided in commmand line
	 * 
	 * @param args
	 */

	public void parser(String[] args) {

		String secureports = "23,34,12,22,69";
		String semisecureports = "179,169,54,34,1024";
		String insecureports = "21,59,67,89";

		StringTokenizer ports = new StringTokenizer(secureports, ",");
		while (ports.hasMoreTokens()) {
			secure.add(Integer.parseInt(ports.nextToken()));

			ports = new StringTokenizer(semisecureports, ",");

			while (ports.hasMoreTokens()) {
				semisecure.add(Integer.parseInt(ports.nextToken()));
			}

			ports = new StringTokenizer(insecureports, ",");
			while (ports.hasMoreTokens()) {
				insecure.add(Integer.parseInt(ports.nextToken()));
			}
		}

		// alpha = Double.parseDouble(args[3]);
		// source = args[4];
		destination = "74.207.244.221";
		fileprefix = "test";
	}

	/**
	 * Function to start the program
	 * 
	 * @throws SQLException
	 * @throws InstantiationException
	 * @throws IllegalAccessException
	 * @throws ClassNotFoundException
	 * @throws InterruptedException
	 * @throws IOException
	 */

	public void routemetric() {

	}

	public static void main(String[] args) throws SQLException,
			InstantiationException, IllegalAccessException,
			ClassNotFoundException, InterruptedException, IOException {

		// check args size

		/*
		 * if (args.length != 6) { System.out.println(" incorrect parameters");
		 * }
		 */

		MetricCal met = new MetricCal();
		met.parser(args);
		Parser parse = new Parser();
		// met.Execute();

		parse.traceParsing(met.fileprefix);
		parse.parsing(met.fileprefix);
		parse.PathParsing();
		parse.tostring();
		met.Security(parse);
		met.Vulnerability(parse);
		met.bandwidth(parse);
		System.out.println();
		String metricstring = met.toString().replaceAll(", ", "-");
		String[] data = metricstring.split(":");

		for (String string : data) {
			System.out.println(string);
		}
	}

}
