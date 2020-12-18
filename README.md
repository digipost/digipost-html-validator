[![Maven Central](https://maven-badges.herokuapp.com/maven-central/no.digipost/digipost-html-validator/badge.svg)](https://maven-badges.herokuapp.com/maven-central/no.digipost/digipost-html-validator)
![](https://github.com/digipost/digipost-html-validator/workflows/Build%20and%20deploy/badge.svg)
[![License](https://img.shields.io/badge/license-Apache%202-blue)](https://github.com/digipost/digipost-html-validator/blob/main/LICENCE)

# digipost-html-validator
Validering og sanitering av html sendt inn til digipost.

`DigipostValidatingHtmlSanitizer` vil sanitere html-dokumentet ditt. Vi anbefaler at du sjekker ditt dokument mot denne vaskingen og justerer ditt dokument til det er minimalt med forskjell (diff).

Digipost vil i alle tilfeller utføre samme sjekk og vask ved innsending og eventuelle videresendinger brevmottagere skulle ville gjøre.

Noen av kravene til html:
* Ingen javascript.
* Ingen eksterne avhengigheter som skal lastes ned (bilder, css, font-er etc.). Alt må inlines.
* Lovlige html-tags og css-atributter er definert gjennom `ApiHtmlValidatorPolicy` (whitelist). 

Se: 
[ApiHtmlValidatorPolicy.java](https://github.com/digipost/digipost-html-validator/blob/master/src/main/java/no/digipost/sanitizing/internal/ApiHtmlValidatorPolicy.java)
[StyleElementPreprocessor.java](https://github.com/digipost/digipost-html-validator/blob/master/src/main/java/no/digipost/sanitizing/internal/StyleElementPreprocessor.java)

# Eksempel

`DigipostValidatingHtmlSanitizer.sanitize` er en BiFunction som tar inn ditt html-dokument som string sammen med en PolicyFactory og returnerer den vaskede html-en.

Vi har en PolicyFactory-implementasjon i Digipost

* `PolicyFactoryProvider.API_HTML`

```java
String inputHtml = [...] // Ditt html-dokument

String sanitizedHtml = DigipostValidatingHtmlSanitizer.sanitize(
    inputHtml
    , PolicyFactoryProvider.API_HTML
);
```

Hvis din html har feil i html vil funksjonen kaste `HTMLValidationException`. Og `CSSValidationException` hvis det er feil i css. Begge exception-typene
arver fra `ValidationException` som er en `RuntimeException` og har metoden `getValidationErrors` for å hente ut feilene i dokumentet.
Se `DigipostValidatingHtmlSanitizerTest` for basic eksempel.  

Det går også an bruke en instans av `HtmlValidator.java`:
```java
HtmlValidationResult validationResult = new HtmlValidator().valider("<html></html>".getBytes());

if(validationResult.okForWeb){
    //Cool! Det kan sendes inn
} else {
    System.err.println(validationResult.toString()); // vil skrive ut meldingene fra exception
}

if(validationResult.hasDiffAfterSanitizing){ // Din html er endret på og er fremdele ok å sende inn.
    System.out.println(validationResult.toString()); // vil skrive ut den nye html-en som du så kan bruke til å endre din html.
}
```

# Hvorfor vasker vi HTML-kode som blir sendt til Digipost
Generelt endrer vi ikke på innhold som blir sendt gjennom Digipost. Men HTML-validering er vanskelig. Å sørge
for at HTML er vasket er mye enklere (se [https://github.com/OWASP/java-html-sanitizer/blob/master/docs/html-validation.md](https://github.com/OWASP/java-html-sanitizer/blob/f1c32172208e29c970d2cdfdd6be48d6d44d3646/docs/html-validation.md).
