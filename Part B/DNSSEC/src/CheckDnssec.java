import java.io.IOException;
import java.net.SocketTimeoutException;
import java.sql.Timestamp;
import java.util.Timer;

import org.xbill.DNS.ARecord;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.DNSSEC.DNSSECException;
import org.xbill.DNS.DSRecord;
import org.xbill.DNS.ExtendedFlags;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.Message;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

public class CheckDnssec {
	static String question = null;
	private static String[] rootServers = new String[] { "198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13",
			"192.203.230", "192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30",
			"193.0.14.129", "199.7.83.42", "202.12.27.33" };
	public static DNSKEYRecord dnskeykskglobal = null;
	static String parentAddress = null;
	static String currentQuery = null;

	static int flagDNSVerification = 2;
	static boolean verifyDSFlag=true;
	public static void main(String[] args) {
		question = args[0];
		long TS = System.currentTimeMillis();
		Message m = resolver(args[0], args[1]);
		long TE = System.currentTimeMillis();
		System.out.println("main message : " + m);
		System.out.println("Time required : " + (TE - TS));
		if (flagDNSVerification == 2) {
			System.out.println("DNSSEC is verified !!!!!");
		} else if (flagDNSVerification == 1) {
			System.out.println("DNSSEC not enabled !!!!");
		} else {
			System.out.println("DNSSEC verification failed");
		}
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
				rootDSverify(concatQuery, HostServer);
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
							//System.out.println("CNAME : " + ((CNAMERecord) AnswerRecords[i]).getTarget());
							m = resolver(((CNAMERecord) AnswerRecords[i]).getTarget().toString(), type);
						} else if (m.getQuestion().getType() == Type.CNAME
								&& AnswerRecords[i].getType() == Type.CNAME) {
							//System.out.println("CNAME : " + ((CNAMERecord) AnswerRecords[i]).getTarget());
						}
						if ((AnswerRecords[i]).getType() == Type.NS) {
							//System.out.println("NS : " + ((NSRecord) AnswerRecords[i]).toString());
						}
						if (AnswerRecords[i].getType() == Type.SOA) {
							//System.out.println("SOA : " + ((SOARecord) AnswerRecords[i]).toString());
						}
						if (AnswerRecords[i].getType() == Type.MX) {
							//System.out.println("MX : " + ((MXRecord) AnswerRecords[i]).toString());
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
							//System.out.println("SOA : " + ((SOARecord) AuthorityRecords[j]).toString());
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
							//System.out.println("NS : " + ((NSRecord) AuthorityRecords[j]).toString());
							if (m.getQuestion().getType() == Type.A) {
								if ((AdditionalRecords.length == 0 && flag == 0)
										|| AdditionalRecords[0].getType() == Type.OPT) {
									//System.out.println("AdditionalRecords ");

									//System.out.println(AuthorityRecords[0].toString());

									Message my = resolver(((NSRecord) AuthorityRecords[0]).getTarget().toString(), "A");
									//System.out.println(my.toString());

									try {
										m = queryServers(concatQuery, ((ARecord) my.getSectionArray(Section.ANSWER)[0])
												.getAddress().getHostAddress(), "A");
									} catch (IOException e) { // TODO Auto-generated catch block
										e.printStackTrace();
									}
									/*System.out.println(
											"Final resolved : " + m.getSectionArray(Section.ANSWER)[0].toString());
									*/if (!question.equals(m.getQuestion().getName())) {
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
											//System.out.println(AuthorityRecords[k].toString());
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
												/*System.out.println("Final resolved : "
														+ m.getSectionArray(Section.ANSWER)[0].toString());
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
								//System.out.println("name and question are equal");

							} else {
								if (splitcount >= 0) {
									concatQuery = resolvedDomain[splitcount] + "." + concatQuery;
								}
							}
							// System.out.println("Concat string" + concatQuery);
							break;
						} else if (AdditionalRecords[k].getType() == Type.A) {
							currentQuery = concatQuery;
							parentAddress = HostServer;
							HostServer = ((ARecord) AdditionalRecords[k]).getAddress().getHostAddress();

							Message messageDNSKEYs = queryServers(currentQuery, HostServer, "DNSKEY");
							DNSKEYRecord dnskeyRecord = null;
							try {
								dnskeyRecord = verifyDNSKEYs(messageDNSKEYs);
							} catch (Exception e) {
								flagDNSVerification = 3;
								flagForResolution=false;
								e.printStackTrace();
							}
							Message message3 = queryServers(currentQuery, parentAddress, "DS");
							try {
								
								verifyDSFlag=verifyDSRecords(message3);
								//System.out.println("verify flag : " + verifyDSFlag);
								if(!verifyDSFlag) {
									flagDNSVerification=3;
									flagForResolution=false;
									break;
								}
							} catch (NullPointerException e) {
								//e.printStackTrace();
								//System.out.println("DNSSEC not enabled!!!!!!!!!!!!!!!");
								flagDNSVerification = 1;
							}
							if (question.equals(concatQuery)) {
								Message message2 = queryServers(currentQuery, HostServer, "A");
								// System.out.println(dnskeyRecord);
								//System.out.println(message2);

								dnsRRSIGVerification(message2, dnskeyRecord);

							} else {
								Message message2 = queryServers(currentQuery, HostServer, "NS");
								// System.out.println(dnskeyRecord);
								//System.out.println(message2);

								dnsRRSIGVerification(message2, dnskeyRecord);

							}
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
		//System.out.println(m);
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
		} else if (queryType.equals("DNSKEY")) {
			return Type.DNSKEY;
		} else if (queryType.equals("ANY")) {
			return Type.ANY;
		} else if (queryType.equals("DS")) {
			return Type.DS;
		}
		return -1;
	}
// Query sending and recieving response 
	private static Message queryServers(String query, String HostServer, String RecordType) throws IOException {
		Message response = null;
		Resolver simpleReso = new SimpleResolver(HostServer);

		Name queryName = Name.fromString(query);
		Record question = Record.newRecord(queryName, queryType(RecordType), DClass.IN);

		Message result = new Message();
		// Header formation
		Header header = result.getHeader();
		header.unsetFlag(Flags.RD);
		simpleReso.setEDNS(0, 0, ExtendedFlags.DO, null);
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
// function to verify RRSIG of DNSKEYs
	private static DNSKEYRecord verifyDNSKEYs(Message message) throws DNSSECException {
		// System.out.println(message);
		DNSKEYRecord dnskeyksk = null;
		DNSKEYRecord dnskeyzsk = null;
		Record[] answerRecords = message.getSectionArray(Section.ANSWER);
		// create rrset
		RRset rRset = new RRset();
		for (int i = 0; i < answerRecords.length; i++) {
			if (answerRecords[i].getType() == Type.DNSKEY) {
				if (((DNSKEYRecord) answerRecords[i]).getFlags() != DNSKEYRecord.Flags.ZONE_KEY) {
					dnskeyksk = ((DNSKEYRecord) answerRecords[i]);
					dnskeykskglobal = dnskeyksk;
				} else if (((DNSKEYRecord) answerRecords[i]).getFlags() == DNSKEYRecord.Flags.ZONE_KEY) {
					dnskeyzsk = ((DNSKEYRecord) answerRecords[i]);
				}
				rRset.addRR(answerRecords[i]);
			}

		}
		for (int i = 0; i < answerRecords.length; i++) {
			if (answerRecords[i].getType() == Type.RRSIG) {
				RRSIGRecord rrsigRecord = (RRSIGRecord) answerRecords[i];

				//System.out.println((RRSIGRecord) answerRecords[i] + "for verification !!!!");
				if (rrsigRecord.getFootprint() == dnskeyksk.getFootprint()) {
					DNSSEC.verify(rRset, (RRSIGRecord) answerRecords[i], dnskeyksk);
				}

			}

		}
		return dnskeyzsk;
	}

	private static void verifyOtherRecords(Message message) {

	}
// verify RRSIG of all the records
	private static void dnsRRSIGVerification(Message m, DNSKEYRecord dnskeyRecord) {

		Record[] AnswerRecords = m.getSectionArray(Section.ANSWER);
		for (int i = 0; i < AnswerRecords.length; i++) {
			/*
			 * if (AnswerRecords[i].getType() == Type.DS) { DSRecord DSRecordtype =
			 * (DSRecord) AnswerRecords[i]; System.out.println(DSRecordtype.getDigest()); }
			 */

			if (AnswerRecords[i].getType() == Type.RRSIG) {
				RRSIGRecord rrsigRecord = (RRSIGRecord) AnswerRecords[i];
				//System.out.println("rrsigRecord.getRRsetType()  : " + rrsigRecord.getFootprint());
				if (rrsigRecord.getRRsetType() == Type.NS) {

					// ASK for DNSKEY this works only for any.........................

					if (dnskeyRecord.getFootprint() == rrsigRecord.getFootprint()) {
						RRset rr = new RRset();
						for (int k = 0; k < m.getSectionArray(Section.ANSWER).length; k++) {
							if (m.getSectionArray(Section.ANSWER)[k].getType() == Type.NS) {
								rr.addRR(m.getSectionArray(Section.ANSWER)[k]);
							}
						}
						try {

							DNSSEC.verify(rr, rrsigRecord, dnskeyRecord);
							;
							/*System.out.println("verified NS set  :" + dnskeyRecord.getFootprint() + "  "
									+ rrsigRecord.getFootprint());

							System.out.println("-----");
*/
						} catch (DNSSECException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

					}

				}
				if (rrsigRecord.getRRsetType() == Type.SOA) {
					//System.out.println(" for soa ");
					for (int j = 0; j < AnswerRecords.length; j++) {

						if (dnskeyRecord.getFootprint() == rrsigRecord.getFootprint()) {
							RRset rr = new RRset();
							for (int k = 0; k < m.getSectionArray(Section.ANSWER).length; k++) {
								if (m.getSectionArray(Section.ANSWER)[k].getType() == Type.SOA) {
									rr.addRR(m.getSectionArray(Section.ANSWER)[k]);
								}
							}
							try {

								DNSSEC.verify(rr, rrsigRecord, dnskeyRecord);
								;
								/*System.out.println("verified SOA set  :" + dnskeyRecord.getFootprint() + "  "
										+ rrsigRecord.getFootprint());*/
							} catch (DNSSECException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}

						}

					}

				}
				if (rrsigRecord.getRRsetType() == Type.DS) {

					//System.out.println(" for soa ");
					for (int j = 0; j < AnswerRecords.length; j++) {

						if (dnskeyRecord.getFootprint() == rrsigRecord.getFootprint()) {
							RRset rr = new RRset();
							for (int k = 0; k < m.getSectionArray(Section.ANSWER).length; k++) {
								if (m.getSectionArray(Section.ANSWER)[k].getType() == Type.DS) {
									rr.addRR(m.getSectionArray(Section.ANSWER)[k]);
								}
							}
							try {

								DNSSEC.verify(rr, rrsigRecord, dnskeyRecord);
								;
								/*System.out.println("verified DS set  :" + dnskeyRecord.getFootprint() + "  "
										+ rrsigRecord.getFootprint());*/
							} catch (DNSSECException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}

						}

					}

				}
				if (rrsigRecord.getRRsetType() == Type.DNSKEY) {

					//System.out.println(" for soa ");
					for (int j = 0; j < AnswerRecords.length; j++) {

						if (dnskeyRecord.getFootprint() == rrsigRecord.getFootprint()) {
							RRset rr = new RRset();
							for (int k = 0; k < m.getSectionArray(Section.ANSWER).length; k++) {
								if (m.getSectionArray(Section.ANSWER)[k].getType() == Type.DNSKEY) {
									rr.addRR(m.getSectionArray(Section.ANSWER)[k]);
								}
							}
							try {

								DNSSEC.verify(rr, rrsigRecord, dnskeyRecord);
								;
								/*System.out.println("verified DNSkey set  :" + dnskeyRecord.getFootprint() + "  "
										+ rrsigRecord.getFootprint());*/
							} catch (DNSSECException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}

						}

					}

				}
			}

		}

		Record[] AuthorityRecords = m.getSectionArray(Section.AUTHORITY);

		for (int i = 0; i < AuthorityRecords.length; i++) {
			if (AuthorityRecords[i].getType() == Type.RRSIG) {
				RRSIGRecord rrsigRecord = (RRSIGRecord) AuthorityRecords[i];
				//System.out.println("rrsigRecord.getRRsetType()  : " + rrsigRecord.getFootprint());
				if (rrsigRecord.getRRsetType() == Type.NS) {
					for (int j = 0; j < AuthorityRecords.length; j++) {
						// ASK for DNSKEY this works only for any.........................

						if (dnskeyRecord.getFootprint() == rrsigRecord.getFootprint()) {
							RRset rr = new RRset();
							for (int k = 0; k < m.getSectionArray(Section.AUTHORITY).length; k++) {
								if (m.getSectionArray(Section.AUTHORITY)[k].getType() == Type.NS) {
									rr.addRR(m.getSectionArray(Section.AUTHORITY)[k]);
								}
							}
							try {

								DNSSEC.verify(rr, rrsigRecord, dnskeyRecord);
								;
								/*System.out.println("verified NS set  :" + dnskeyRecord.getFootprint() + "  "
										+ rrsigRecord.getFootprint());

								System.out.println("-----");
*/
							} catch (DNSSECException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}

						}

					}

				}
				if (rrsigRecord.getRRsetType() == Type.SOA) {
					//System.out.println(" for soa ");
					for (int j = 0; j < AuthorityRecords.length; j++) {

						if (dnskeyRecord.getFootprint() == rrsigRecord.getFootprint()) {
							RRset rr = new RRset();
							for (int k = 0; k < m.getSectionArray(Section.AUTHORITY).length; k++) {
								if (m.getSectionArray(Section.AUTHORITY)[k].getType() == Type.SOA) {
									rr.addRR(m.getSectionArray(Section.AUTHORITY)[k]);
								}
							}
							try {

								DNSSEC.verify(rr, rrsigRecord, dnskeyRecord);
								/*;
								System.out.println("verified NS set  :" + dnskeyRecord.getFootprint() + "  "
										+ rrsigRecord.getFootprint());*/
							} catch (DNSSECException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}

						}

					}

				}
				if (rrsigRecord.getRRsetType() == Type.DS) {

					//System.out.println(" for soa ");
					for (int j = 0; j < AuthorityRecords.length; j++) {

						if (dnskeyRecord.getFootprint() == rrsigRecord.getFootprint()) {
							RRset rr = new RRset();
							for (int k = 0; k < m.getSectionArray(Section.AUTHORITY).length; k++) {
								if (m.getSectionArray(Section.AUTHORITY)[k].getType() == Type.DS) {
									rr.addRR(m.getSectionArray(Section.AUTHORITY)[k]);
								}
							}
							try {

								DNSSEC.verify(rr, rrsigRecord, dnskeyRecord);
								/*;
								System.out.println("verified DS set  :" + dnskeyRecord.getFootprint() + "  "
										+ rrsigRecord.getFootprint());*/
							} catch (DNSSECException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}

						}

					}

				}
			}

		}

		Record[] AdditionalRecords = m.getSectionArray(Section.ADDITIONAL);
		// System.out.println(m);

	}
// to verify DS records
	private static boolean verifyDSRecords(Message m) {

		/*System.out.println("DS records");
		System.out.println(m);*/
		boolean verifyFlag = true;
		DSRecord dsRecord = null;
		Record[] answerrecords = m.getSectionArray(Section.ANSWER);
		for (int i = 0; i < answerrecords.length; i++) {
			if (answerrecords[i].getType() == Type.DS) {
				dsRecord = (DSRecord) answerrecords[i];
			}
		}
		DSRecord dsRecordfromkey = new DSRecord(dsRecord.getName(), DClass.IN, dsRecord.getTTL(),
				dsRecord.getDigestID(), dnskeykskglobal);

		/*System.out.println(dsRecordfromkey);
		System.out.println(dsRecord);*/
		for (int i = 0; i < dsRecord.getDigest().length; i++) {
			if (dsRecord.getDigest()[i] != dsRecordfromkey.getDigest()[i]) {
				verifyFlag = false;
				break;
			}
		}

		return verifyFlag;

	}
// verify KSK of root to DS trust key (DS)
	private static boolean rootDSverify(String tld, String rootServer) {
		boolean verificationFlag = false;
		Message mDnSkey = null;
		try {
			mDnSkey = queryServers(".", rootServer, "DNSKEY");
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		DNSKEYRecord dnskeyksk = null;
		Record[] answerRecords = mDnSkey.getSectionArray(Section.ANSWER);
		for (int i = 0; i < answerRecords.length; i++) {
			if (answerRecords[i].getType() == Type.DNSKEY) {
				if (((DNSKEYRecord) answerRecords[i]).getFlags() != DNSKEYRecord.Flags.ZONE_KEY) {
					dnskeyksk = ((DNSKEYRecord) answerRecords[i]);
					// dnskeykskglobal = dnskeyksk;
				}
			}
		}

		String DS = "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";
		DSRecord dsRecordfromkey;
		try {
			dsRecordfromkey = new DSRecord(new Name(tld), DClass.IN, 1000, 2, dnskeyksk);
			/*System.out.println(dsRecordfromkey.getDigest().toString());
			System.out.println(dsRecordfromkey);
			// System.out.println(DS.equals(dsRecordfromkey.getDigest().toString()));
			System.out.println("Root DS verification " + dsRecordfromkey.toString().contains(DS));*/
			verificationFlag = dsRecordfromkey.toString().contains(DS);
		} catch (TextParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// HMAC hmac = new HMAC(Algorithm.string(dsRecord.getAlgorithm()),
		// dnskeyRecord.getKey());
		// hmac.verify(signature)

		// System.out.println(hmac.verify(dsRecord.getDigest()));

		return verificationFlag;

	}
}
