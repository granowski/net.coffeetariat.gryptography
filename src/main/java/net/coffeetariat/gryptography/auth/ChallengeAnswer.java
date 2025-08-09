package net.coffeetariat.gryptography.auth;

public class ChallengeAnswer {
  public String sessionId;
  public String answer;

  public ChallengeAnswer(String id, String answer) {
    this.sessionId = id;
    this.answer = answer;
  }
}
