/*
 * Copyright 1999-2006 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.globus.security.util;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.Vector;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.globus.security.SigningPolicy;
import org.globus.security.SigningPolicyException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Signing policy BCNF grammar as implemented here: (based on C implementation)
 * <p/>
 * eacl ::=  {eacl_entry} eacl_entry ::= {access_identity} pos_rights
 * {restriction} {pos_rights {restriction}} | {access_identity} neg_rights
 * access_identity ::= access_identity_type  def_authority  value  \n
 * access_identity_type ::= "access_id_HOST"  | "access_id_USER"  |
 * "access_id_GROUP" | "access_id_CA"    | "access_id_APPLICATION" |
 * "access_id_ANYBODY" pos_rights ::=  "pos_rights" def_authority value
 * {"pos_rights" def_authority value} neg_rights ::= "neg_rights" def_authority
 * value {"neg_rights" def_authority value} restriction ::= condition_type
 * def_authority  value  \n condition_type ::= alphanumeric_string def_authority
 * ::= alphanumeric_string value ::= alphanumeric_string
 * <p/>
 * This class take a signing policy file as input and parses it to extract the
 * policy that is enforced. Only the following policy is enforced: access_id_CA
 * with defining authority as X509 with CA DN as value. Any positive rights
 * following it with globus as defining authority and value CA:sign. Lastly,
 * restriction "cond_subjects" with globus as defining authority and the DNs the
 * CA is authorized to sign. restrictions are assumed to start with cond_. Order
 * of rights matter, so the first occurance of CA:Sign with allowedDNs is used
 * and rest of the policy is ignored.
 * <p/>
 * For a given signing policy file, only policy with the particular CA's DN is
 * parsed.
 * <p/>
 * subject names may include the following wildcard characters: *    Matches
 * zero or any number of characters. ?    Matches any single character.
 * <p/>
 * All subject names should be in Globus format, with slashes and should NOT be
 * revered.
 * <p/>
 * The allowed DN patterns are returned as a vector of java.util.regexp.Pattern.
 * The BCNF grammar that uses wildcard (*) and single character (?) are replaced
 * with the regexp grammar needed by the Pattern class.
 */
public class SigningPolicyFileParser {

    public static final String ACCESS_ID_PREFIX = "access_id_";
    public static final String ACCESS_ID_CA = "access_id_CA";

    public static final String DEF_AUTH_X509 = "X509";
    public static final String DEF_AUTH_GLOBUS = "globus";

    public static final String POS_RIGHTS = "pos_rights";
    public static final String NEG_RIGHTS = "neg_rights";

    public static final String CONDITION_PREFIX = "cond_";
    public static final String CONDITION_SUBJECT = "cond_subjects";

    public static final String VALUE_CA_SIGN = "CA:sign";

    public static final String SINGLE_CHAR = "?";
    public static final String WILDCARD = "*";

    public static final String SINGLE_PATTERN = "[\\p{Print}\\p{Blank}]";
    public static final String WILDCARD_PATTERN = SINGLE_PATTERN + "*";

    static final String[] ALLOWED_LINE_START =
        new String[]{ACCESS_ID_PREFIX, POS_RIGHTS, NEG_RIGHTS,
            CONDITION_PREFIX};

    private Logger logger =
        LoggerFactory.getLogger(SigningPolicyFileParser.class.getName());

    /**
     * Parses the file to extract signing policy defined for CA with the
     * specified DN. If the policy file does not exist, a SigningPolicy object
     * with only CA DN is created. If policy path exists, but no relevant policy
     * exisit, SigningPolicy object with CA DN and file path is created.
     *
     * @param fileName Name of the signing policy file
     * @return SigningPolicy object that contains the information. If no policy
     *         is found, SigningPolicy object with only the CA DN is returned.
     * @throws org.globus.security.SigningPolicyException
     *          Any errors with parsing the signing policy file.
     */
    public Map<X500Principal, SigningPolicy> parse(String fileName)
        throws FileNotFoundException, SigningPolicyException {

        if ((fileName == null) || (fileName.trim().equals(""))) {
            throw new IllegalArgumentException();
        }

        logger.debug("Signing policy file name " + fileName);

        FileReader fileReader = null;

        try {
            fileReader = new FileReader(fileName);
            return parse(fileReader);
        } catch (Exception e) {
            throw new SigningPolicyException(e);
        } finally {
            if (fileReader != null) {
                try {
                    fileReader.close();
                } catch (Exception exp) {
                    logger.debug("Error closing file reader", exp);
                }
            }
        }


    }

    /**
     * Parses input stream to extract signing policy defined for CA with the
     * specified DN.
     *
     * @param reader Reader to any input stream to get the signing policy
     *               information.
     * @throws org.globus.security.SigningPolicyException
     *          Any errors with parsing the signing policy.
     */
    public Map<X500Principal, SigningPolicy> parse(Reader reader)
        throws SigningPolicyException {

        Map<X500Principal, SigningPolicy> policies = new HashMap<X500Principal, SigningPolicy>();

        BufferedReader bufferedReader = new BufferedReader(reader);
        try {
            String line;

            while ((line = bufferedReader.readLine()) != null) {

                line = line.trim();

                // read line until some line that needs to be parsed.
                if (!isValidLine(line)) {
                    continue;
                }

                logger.trace("Line to parse: " + line);

                String caDN = null;
                if (line.startsWith(ACCESS_ID_PREFIX)) {

                    logger.trace("Check if it is CA and get the DN " + line);

                    if (line.startsWith(ACCESS_ID_CA)) {
                        caDN = getCA(line.substring(ACCESS_ID_CA.length(),
                            line.length()));
                        logger.trace("CA DN is " + caDN);
                    }

                    boolean usefulEntry = true;

                    Boolean posNegRights = null;
                    // check for neg or pos rights with restrictions
                    while ((line = bufferedReader.readLine()) != null) {

                        if (!isValidLine(line)) {
                            continue;
                        }

                        line = line.trim();

                        logger.trace("Line is " + line);

                        if (line.startsWith(POS_RIGHTS)) {
                            if (Boolean.FALSE.equals(posNegRights)) {
                                String err = "invlaidPosRights";
                                //  i18n.getMessage("invalidPosRights", line);
                                throw new SigningPolicyException(err);
                            }
                            posNegRights = Boolean.TRUE;
                            if (usefulEntry) {
                                logger.trace("Parse pos_rights here");
                                int startIndex = POS_RIGHTS.length();
                                int endIndex = line.length();
                                // if it is not CASignRight, then
                                // usefulentry will be false. Otherwise
                                // other restrictions will be useful.
                                usefulEntry = isCASignRight(line.substring(startIndex, endIndex));
                            }
                        } else if (line.startsWith(NEG_RIGHTS)) {

                            if (Boolean.TRUE.equals(posNegRights)) {
                                String err = "invalidNegRights";
                                //  i18n.getMessage("invalidNegRights", line);
                                throw new SigningPolicyException(err);
                            }
                            posNegRights = Boolean.FALSE;
                            logger.trace("Ignore neg_rights");

                        } else if (line.startsWith(CONDITION_PREFIX)) {

                            if (!Boolean.TRUE.equals(posNegRights)) {
                                String err = "invalidRestrictions";
                                //   i18n.getMessage("invalidRestrictions", line);
                                throw new SigningPolicyException(err);
                            }

                            if (usefulEntry && line.startsWith(CONDITION_SUBJECT)) {
                                logger.trace("Read in subject condition.");
                                int startIndex =
                                    CONDITION_SUBJECT.length();
                                int endIndex = line.length();
                                Vector<Pattern> allowedDNs = getAllowedDNs(line.substring(startIndex, endIndex));
                                X500Principal caPrincipal
                                    = CertificateUtil.toPrincipal(caDN);
                                SigningPolicy policy = new SigningPolicy(caPrincipal, allowedDNs);
                                policies.put(caPrincipal, policy);
                                break;
                            }
                        } else {
                            String err = "invalidLIne";
                            // no valid start with
                            // String err = i18n.getMessage("invalidLine", line);
                            throw new SigningPolicyException(err + line);
                        }
                    }
                }
                // entry needs to start with that.
                //String err = i18n.getMessage("invalidAccessId", line);
                //   String err = "invalidAccessId";
                // throw new SigningPolicyException(err);
                // FIXME: look for correct line?
            }
        } catch (IOException exp) {
            throw new SigningPolicyException("", exp);
        } finally {
            if (bufferedReader != null) {
                try {
                    bufferedReader.close();
                } catch (Exception exp) {
                    //Nothing we can do
                    logger.debug("Unable to close bufferedReader", exp);
                }
            }
            if (reader != null) {
                try {
                    reader.close();
                } catch (Exception e) {
                    //Nothing we can do
                    logger.debug("Unable to close reader", e);
                }
            }
        }
        return policies;
    }

    private boolean isValidLine(String line)
        throws SigningPolicyException {

        line = line.trim();

        // if line is empty or comment character, skip it.
        if (line.equals("") || line.startsWith("#")) {
            return false;
        }

        // Validate that there are atleast three tokens on the line
        StringTokenizer tokenizer = new StringTokenizer(line);
        if (tokenizer.countTokens() < 3) {
            // String err = i18n.getMessage("invalidTokens", line);
            String err = "invalidTokens";
            throw new SigningPolicyException(err);
        }

        for (int i = 0; i < ALLOWED_LINE_START.length; i++) {
            if (line.startsWith(ALLOWED_LINE_START[i])) {
                return true;
            }
        }
        throw new SigningPolicyException("Line starts incorrectly");

    }

    private Vector<Pattern> getAllowedDNs(String line)
        throws SigningPolicyException {

        line = line.trim();

        int index = findIndex(line);

        if (index == -1) {
            String err = "invalid tokens";
            //  i18n.getMessage("invalidTokens", line);
            throw new SigningPolicyException(err);
        }

        String defAuth = line.substring(0, index);

        if (DEF_AUTH_GLOBUS.equals(defAuth)) {

            String value = line.substring(index + 1, line.length());
            value = value.trim();

            int startIndex = 0;
            int endIndex = value.length();
            if (value.charAt(startIndex) == '\'') {
                startIndex++;
                int endOfDNIndex = value.indexOf('\'', startIndex);
                if (endOfDNIndex == -1) {
                    String err = "invlaid subjects";
                    //i18n.getMessage("invalidSubjects",
                    //                       lineForErr);
                    throw new SigningPolicyException(err);
                }
                endIndex = endOfDNIndex;
            }

            value = value.substring(startIndex, endIndex);
            value = value.trim();

            if (value.equals("")) {
                String err = "empty subjects";
                //i18n.getMessage("emptySubjects", lineForErr);
                throw new SigningPolicyException(err);
            }

            Vector<Pattern> vector = new Vector<Pattern>();

            startIndex = 0;
            endIndex = value.length();
            if (value.indexOf("\"") == -1) {
                vector.add(getPattern(value));
            } else {
                while (startIndex < endIndex) {

                    int quot1 = value.indexOf("\"", startIndex);
                    int quot2 = value.indexOf("\"", quot1 + 1);
                    if (quot2 == -1) {
                        String err = "unmatched quotes";
                        //i18n.getMessage("unmatchedQuotes",
                        //                      lineForErr);
                        throw new SigningPolicyException(err);
                    }
                    String token = value.substring(quot1 + 1, quot2);
                    vector.add(getPattern(token));
                    startIndex = quot2 + 1;
                }
            }

            return vector;
        }
        return null;
    }

    private boolean isCASignRight(String line)
        throws SigningPolicyException {

        line = line.trim();

        int index = findIndex(line);

        if (index == -1) {
            String err = "invalid tokens";
            //    i18n.getMessage("invalidTokens", line);
            throw new SigningPolicyException(err);
        }

        String defAuth = line.substring(0, index);
        if (DEF_AUTH_GLOBUS.equals(defAuth)) {
            line = line.substring(index + 1, line.length());
            line = line.trim();
            // check if it is CA:Sign
            String value = line.substring(0, line.length());
            if (VALUE_CA_SIGN.equals(value)) {
                return true;
            }
        }

        return false;
    }

    private String getCA(String inputLine)
        throws SigningPolicyException {

        String line = inputLine.trim();

        int index = findIndex(line);

        if (index == -1) {
            String err = "invalid tokens";
            //  i18n.getMessage("invalidTokens", line);
            throw new SigningPolicyException(err);
        }

        String defAuth = line.substring(0, index);

        if (DEF_AUTH_X509.equals(defAuth)) {

            line = line.substring(index + 1, line.length());
            line = line.trim();

//            String dnString = line.substring(0, line.length());

            String caDN;
            // find CA DN
            int caDNLocation = 0;
            if (line.charAt(caDNLocation) == '\'') {
                caDNLocation++;
                int endofDNIndex = line.indexOf('\'', caDNLocation + 1);
                if (endofDNIndex == -1) {
                    //  String err = i18n.getMessage("invalidCaDN", inputLine);
                    String err = "invalid ca dn";
                    throw new SigningPolicyException(err);
                }
                caDN = line.substring(caDNLocation, endofDNIndex);
            } else {
                caDN = line.substring(caDNLocation, line.length() - 1);
            }
            caDN = caDN.trim();
            return caDN;
        }
        return null;
    }

    /**
     * Method that takes a pattern string as described in the signing policy
     * file with * for zero or many characters and ? for single character, and
     * converts it into java.util.regexp.Pattern object. This requires replacing
     * the wildcard characters with equivalent expression in regexp grammar.
     *
     * @param patternStr Pattern string as described in the signing policy file
     *                   with for zero or many characters and ? for single
     *                   character
     * @return Pattern object with the expression equivalent to patternStr.
     */
    public static Pattern getPattern(String patternStr) {

        if (patternStr == null) {
            throw new IllegalArgumentException();
        }

        int startIndex = 0;
        int endIndex = patternStr.length();
        StringBuffer buffer = new StringBuffer("");
        while (startIndex < endIndex) {
            int star = patternStr.indexOf(WILDCARD, startIndex);
            if (star == -1) {
                star = endIndex;
                String preStr = patternStr.substring(startIndex, star);
                buffer = buffer.append(preStr);
            } else {
                String preStr = patternStr.substring(startIndex, star);
                buffer = buffer.append(preStr).append(WILDCARD_PATTERN);
            }
            startIndex = star + 1;
        }

        patternStr = buffer.toString();

        startIndex = 0;
        endIndex = patternStr.length();
        buffer = new StringBuffer("");
        while (startIndex < endIndex) {
            int qMark = patternStr.indexOf(SINGLE_CHAR, startIndex);
            if (qMark == -1) {
                qMark = endIndex;
                String preStr = patternStr.substring(startIndex, qMark);
                buffer = buffer.append(preStr);
            } else {
                String preStr = patternStr.substring(startIndex, qMark);
                buffer = buffer.append(preStr).append(SINGLE_PATTERN);
            }
            startIndex = qMark + 1;
        }
        patternStr = buffer.toString();

        LoggerFactory.getLogger(SigningPolicyFileParser.class).debug("String with replaced pattern is " + patternStr);

        return Pattern.compile(patternStr, Pattern.CASE_INSENSITIVE);
    }

    // find first space or tab as separator.

    private int findIndex(String line) {

        int index = -1;

        if (line == null) {
            return index;
        }

        line = line.trim();
        int spaceIndex = line.indexOf(" ");
        int tabIndex = line.indexOf("\t");

        if (spaceIndex != -1) {
            if (tabIndex != -1) {
                if (spaceIndex < tabIndex) {
                    index = spaceIndex;
                } else {
                    index = tabIndex;
                }
            } else {
                index = spaceIndex;
            }
        } else {
            index = tabIndex;
        }
        return index;
    }
}
