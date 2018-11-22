import java.io.IOException;
import java.net.SocketTimeoutException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Timer;

import org.xbill.DNS.ARecord;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.Message;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

public class Experiment {
	static String question = null;
	private static String[] rootServers = new String[] { "198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13",
			"192.203.230", "192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30",
			"193.0.14.129", "199.7.83.42", "202.12.27.33" };
	static List<Record> toAppendInAnswerSecton = new ArrayList<Record>();

	public static void main(String[] args) {
		question = args[0];
		long TS = System.currentTimeMillis();
		Message m = resolver(args[0], args[1]);
		long TE = System.currentTimeMillis();
		// System.out.println("main message : " + m);
		m.removeAllRecords(Section.QUESTION);

		// final record

		// Resolver simpleReso = new SimpleResolver(HostServer);

		Name queryName = null;
		try {
			queryName = Name.fromString(args[0]);
		} catch (TextParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		Record question = Record.newRecord(queryName, queryType(args[1]), DClass.IN);

		/*
		 * Message response = new Message(); // Header formation
		 * 
		 * Header header = response.getHeader(); header.unsetFlag(Flags.RD);
		 * 
		 * // header.setFlag(Flags.AA);
		 * 
		 * response.setHeader(m.getHeader());
		 * response.removeAllRecords(Section.QUESTION);
		 * response.removeAllRecords(Section.ANSWER);
		 * response.removeAllRecords(Section.AUTHORITY);
		 * response.removeAllRecords(Section.ADDITIONAL); response.addRecord(question,
		 * 0);
		 * 
		 * Record[] AnswerRecords = m.getSectionArray(Section.ANSWER); for (int i = 0; i
		 * < AnswerRecords.length; i++) { response.addRecord(AnswerRecords[i],
		 * Section.ANSWER); }
		 * 
		 * Record[] AuthorityRecords = m.getSectionArray(Section.AUTHORITY); for (int i
		 * = 0; i < AuthorityRecords.length; i++) {
		 * response.addRecord(AuthorityRecords[i], Section.AUTHORITY); }
		 * 
		 * Record[] AdditionalRecords = m.getSectionArray(Section.ADDITIONAL); for (int
		 * i = 0; i < AdditionalRecords.length; i++) {
		 * response.addRecord(AdditionalRecords[i], Section.ADDITIONAL); }
		 * 
		 */ m.addRecord(question, Section.QUESTION);
		for (Record r : toAppendInAnswerSecton) {
			m.addRecord(r, Section.ANSWER);
		}
		System.out.println(m);
		System.out.println("Query Time : " + (TE - TS));
		System.out.println("when : " + new Date());

	}
// iterative resolver
	private static Message resolver(String query, String type) {
		boolean flagItrRootServers = true;
		int count = 0;
		boolean flagForResolution = true;
		Message m = null;
		String[] resolvedDomain = query.split("\\.");
		String concatQuery = null;
		// to terminate special case
		boolean flagForOneItr = false;
		while (flagItrRootServers) {
			try {
				flagItrRootServers = false;
				String HostServer = null;
				HostServer = rootServers[count];
				int splitcount = resolvedDomain.length - 1;
				concatQuery = resolvedDomain[splitcount] + ".";
				int flag = 0;
				while (flagForResolution) {
					splitcount--;

					m = null;

					m = queryServers(concatQuery, HostServer, type);

					flagForResolution = !m.getHeader().getFlag(Flags.AA);

					Record[] AnswerRecords = m.getSectionArray(Section.ANSWER);

					Record[] AuthorityRecords = m.getSectionArray(Section.AUTHORITY);

					Record[] AdditionalRecords = m.getSectionArray(Section.ADDITIONAL);

					for (int i = 0; i < AnswerRecords.length; i++) {
						// check for A record
						// else check for CNAME record
						// resolve CNAME from start

						if ((AnswerRecords[i]).getType() == Type.A) {
							HostServer = ((ARecord) AnswerRecords[i]).getAddress().getHostAddress();
							return m;
							// flagForResolution=false;
						}
						if (m.getQuestion().getType() == Type.A && AnswerRecords[i].getType() == Type.CNAME) {
							// System.out.println("CNAME : " + ((CNAMERecord)
							// AnswerRecords[i]).getTarget());
							toAppendInAnswerSecton.add((CNAMERecord) AnswerRecords[i]);
							m = resolver(((CNAMERecord) AnswerRecords[i]).getTarget().toString(), type);
						} else if (m.getQuestion().getType() == Type.CNAME
								&& AnswerRecords[i].getType() == Type.CNAME) {
							// System.out.println("CNAME : " + ((CNAMERecord)
							// AnswerRecords[i]).getTarget());
						}
						if ((AnswerRecords[i]).getType() == Type.NS) {
							// System.out.println("NS : " + ((NSRecord) AnswerRecords[i]).toString());
						}
						if (AnswerRecords[i].getType() == Type.SOA) {
							// System.out.println("SOA : " + ((SOARecord) AnswerRecords[i]).toString());
						}
						if (AnswerRecords[i].getType() == Type.MX) {
							// System.out.println("MX : " + ((MXRecord) AnswerRecords[i]).toString());
							/*
							 * if (!m.getQuestion().getName().equals(question)) { if (splitcount >= 0) {
							 * concatQuery = resolvedDomain[splitcount] + "." + concatQuery; }
							 * flagForResolution = true; } else { System.out.println(); } break;
							 */
							/*
							 * flagForResolution = false; break;
							 */
						}

					}
					for (int j = 0; j < AuthorityRecords.length; j++) {

						if (AuthorityRecords[j].getType() == Type.SOA) {
							// System.out.println("SOA : " + ((SOARecord) AuthorityRecords[j]).toString());
							if (m.getQuestion().getType() == Type.A) {
								if (concatQuery.equals(question)) {
									flagForResolution = false;
								} else {
									if (splitcount >= 0) {
										concatQuery = resolvedDomain[splitcount] + "." + concatQuery;
									}
									flagForResolution = true;
									flag = 1;
								}
							}

						}
						if (AuthorityRecords[j].getType() == Type.NS) {
							// System.out.println("NS : " + ((NSRecord) AuthorityRecords[j]).toString());
							if (m.getQuestion().getType() == Type.NS && AdditionalRecords.length == 0) {
								if (m.getQuestion().getName().toString().equals(question)) {
									flagForResolution = false;
								}
							}
							if (m.getQuestion().getType() == Type.A) {
								if (AdditionalRecords.length == 0 && flag == 0) {
									// System.out.println("AdditionalRecords ");

									// System.out.println(AuthorityRecords[0].toString());

									Message my = resolver(((NSRecord) AuthorityRecords[0]).getTarget().toString(), "A");
									// System.out.println(my.toString());

									try {
										m = queryServers(concatQuery, ((ARecord) my.getSectionArray(Section.ANSWER)[0])
												.getAddress().getHostAddress(), "A");
									} catch (IOException e) { // TODO Auto-generated catch block
										e.printStackTrace();
									}
									/*
									 * System.out.println( "Final resolved : " +
									 * m.getSectionArray(Section.ANSWER)[0].toString());
									 */
									if (!question.equals(m.getQuestion().getName())) {
										m = queryServers(question, ((ARecord) my.getSectionArray(Section.ANSWER)[0])
												.getAddress().getHostAddress(), "A");
									}

									flagForResolution = false;
									flag = 0;

									break;

								}

								if (flag == 1 && AdditionalRecords.length == 0) {
									for (int k = 0; k < AuthorityRecords.length; k++) {
										if (AuthorityRecords[k].getType() == Type.NS) {
											// System.out.println(AuthorityRecords[k].toString());
											flagForResolution = false;
											Message my = resolver(
													((NSRecord) AuthorityRecords[k]).getTarget().toString(), "A");
											if (my.getHeader().getFlag(Flags.AA)) {
												if (splitcount >= 0) {
													concatQuery = resolvedDomain[splitcount] + "." + concatQuery;
												}
												Message my2 = null;
												try {
													m = queryServers(concatQuery,
															((ARecord) my.getSectionArray(Section.ANSWER)[0])
																	.getAddress().getHostAddress(),
															"A");
												} catch (IOException e) {
													// TODO Auto-generated catch block
													e.printStackTrace();
												}
												/*
												 * System.out.println("Final resolved : " +
												 * m.getSectionArray(Section.ANSWER)[0].toString());
												 */
												flag = 0;
											}
											break;
										}
										break;

									}

								}
							}
						}

					}
					for (int k = 0; k < AdditionalRecords.length; k++) {

						if (m.getQuestion().getType() == Type.MX && AdditionalRecords[k].getType() == Type.A) {
							// System.out.println("inside additional Mx");
							HostServer = ((ARecord) AdditionalRecords[k]).getAddress().getHostAddress();
							// System.out.println("m.getQuestion().getName()) " +
							// m.getQuestion().getName());
							if (question.equals(m.getQuestion().getName().toString())) {
								// System.out.println("name and question are equal");

							} else {
								if (splitcount >= 0) {
									concatQuery = resolvedDomain[splitcount] + "." + concatQuery;
								}
							}
							// System.out.println("Concat string" + concatQuery);
							break;
						} else if (AdditionalRecords[k].getType() == Type.A) {
							HostServer = ((ARecord) AdditionalRecords[k]).getAddress().getHostAddress();
							if (splitcount >= 0) {
								concatQuery = resolvedDomain[splitcount] + "." + concatQuery;
							}
							// not brreaking resolving loop
							break;
						}

					}

				}
			} catch (IOException e) {
				flagItrRootServers = true;
				return null;
			}
		}
		// System.out.println(m);
		return m;

	}

	private static int queryType(String queryType) {
		if (queryType.equals("A")) {
			return Type.A;
		} else if (queryType.equals("NS")) {
			return Type.NS;
		} else if (queryType.equals("CNAME")) {
			return Type.CNAME;
		} else if (queryType.equals("MX")) {
			return Type.MX;
		}
		return -1;
	}
// send query to the server and recieve response
	private static Message queryServers(String query, String HostServer, String RecordType) throws IOException {
		Message response = null;
		Resolver simpleReso = new SimpleResolver(HostServer);

		Name queryName = Name.fromString(query);
		Record question = Record.newRecord(queryName, queryType(RecordType), DClass.IN);

		Message result = new Message();
		// Header formation
		Header header = result.getHeader();
		header.unsetFlag(Flags.RD);
		// header.setFlag(Flags.AA);
		result.setHeader(header);
		result.removeAllRecords(Section.QUESTION);
		result.addRecord(question, 0);
		// System.out.println(result.toString());

		// System.out.println("------------------------------------------------------------------");
		response = simpleReso.send(result);
		// System.out.println(response);
		return response;
	}

	private static boolean verifyDNSSEC(Message m) {
		boolean verified = false;
		return verified;
	}

	private static void dnssecVerification(Message m) {

	}
}
