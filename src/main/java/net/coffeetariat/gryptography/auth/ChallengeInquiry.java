package net.coffeetariat.gryptography.auth;

import net.coffeetariat.gryptography.lib.Utilities;

public class ChallengeInquiry {
  public String sessionId;
  public String inquiry;

  public ChallengeInquiry(String id, String inquiry) {
    this.sessionId = id;
    this.inquiry = inquiry;
  }

  public void debugPrint() {
    System.out.println("session-id: " + sessionId + "; inquiry: " + inquiry);
  }

  /**
   * Minimal JSON serialization without external libraries.
   */
  public String toJson() {
    String sess = Utilities.jsonEscape(this.sessionId);
    String inq = Utilities.jsonEscape(this.inquiry);
    return "{\"sessionId\":\"" + sess + "\",\"inquiry\":\"" + inq + "\"}";
  }

  /**
   * Minimal YAML serialization for ChallengeInquiry.
   */
  public String toYaml() {
    String sess = Utilities.yamlEscape(this.sessionId);
    String inq = Utilities.yamlEscape(this.inquiry);
    return "sessionId: '" + sess + "'\n" +
           "inquiry: '" + inq + "'\n";
  }
}
