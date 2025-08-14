package net.coffeetariat.gryptography.auth;

public class ChallengeAnswer {
  public String sessionId;
  public String answer;
  public String signature;

  public ChallengeAnswer(String id, String answer, String signature) {
    this.sessionId = id;
    this.answer = answer;
    this.signature = signature;
  }
}
