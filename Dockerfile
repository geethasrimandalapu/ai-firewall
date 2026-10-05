# --- build stage ---
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .
RUN mvn -q dependency:go-offline
COPY src ./src
RUN mvn -q package -DskipTests

# --- run stage ---
FROM eclipse-temurin:21-jre
WORKDIR /app
RUN useradd --system --uid 10001 firewall && mkdir -p /app/data && chown firewall /app/data
COPY --from=build /app/target/ai-firewall-*.jar app.jar
USER firewall
EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "app.jar"]
