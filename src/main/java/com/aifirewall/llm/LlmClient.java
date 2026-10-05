package com.aifirewall.llm;

import com.aifirewall.config.FirewallProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/** Forwards OpenAI-format chat requests to the configured upstream model (or a local mock). */
@Component
public class LlmClient {

    private final RestClient restClient;
    private final FirewallProperties props;
    private final ObjectMapper mapper;

    public LlmClient(RestClient llmRestClient, FirewallProperties props, ObjectMapper mapper) {
        this.restClient = llmRestClient;
        this.props = props;
        this.mapper = mapper;
    }

    public JsonNode chat(ObjectNode request) {
        if (!request.hasNonNull("model")) {
            request.put("model", props.upstream().model());
        }
        request.put("stream", false); // v0.1: non-streaming only
        if (props.upstream().mock()) {
            return mockResponse(request);
        }
        return restClient.post()
                .uri("/chat/completions")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + props.upstream().apiKey())
                .contentType(MediaType.APPLICATION_JSON)
                .body(request)
                .retrieve()
                .body(JsonNode.class);
    }

    /** Offline stand-in: echoes exactly what the model would have seen (after redaction). */
    private JsonNode mockResponse(ObjectNode request) {
        JsonNode messages = request.path("messages");
        String lastUser = "";
        for (JsonNode m : messages) {
            if ("user".equals(m.path("role").asText())) {
                lastUser = m.path("content").asText();
            }
        }
        String answer = "[mock model] The model received: \"" + lastUser
                + "\". Set LLM_API_KEY to use a real model.";
        ObjectNode resp = mapper.createObjectNode();
        resp.put("id", "mock-" + System.currentTimeMillis());
        resp.put("object", "chat.completion");
        resp.put("model", "mock-" + request.path("model").asText());
        ObjectNode choice = resp.putArray("choices").addObject();
        choice.put("index", 0);
        choice.put("finish_reason", "stop");
        ObjectNode msg = choice.putObject("message");
        msg.put("role", "assistant");
        msg.put("content", answer);
        ObjectNode usage = resp.putObject("usage");
        int promptTokens = Math.max(1, request.toString().length() / 4);
        int completionTokens = Math.max(1, answer.length() / 4);
        usage.put("prompt_tokens", promptTokens);
        usage.put("completion_tokens", completionTokens);
        usage.put("total_tokens", promptTokens + completionTokens);
        return resp;
    }
}
