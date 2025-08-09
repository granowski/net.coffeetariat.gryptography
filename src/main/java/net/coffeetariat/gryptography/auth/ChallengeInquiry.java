package net.coffeetariat.gryptography.auth;

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
}
