package net.coffeetariat.gryptography.api;

/**
 * Enumeration of media (MIME) types used in this project.
 */
public enum MediaTypes {
  TEXT_PLAIN("text/plain"),
  APPLICATION_JSON("application/json"),
  APPLICATION_YAML("application/yaml"),
  TEXT_YAML("text/yaml"),
  APPLICATION_X_YAML("application/x-yaml");

  private final String value;

  MediaTypes(String value) {
    this.value = value;
  }

  public String value() {
    return value;
  }

  @Override
  public String toString() {
    return value;
  }
}
