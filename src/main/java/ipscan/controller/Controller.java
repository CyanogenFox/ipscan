package ipscan.controller;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.javalin.Javalin;
import io.javalin.http.HttpStatus;
import ipscan.client.SimpleClient;
import ipscan.model.IPResponse;

public class Controller {

	private Javalin app;
	private SimpleClient client;
	private ObjectMapper mapper;

	public Controller() {
		client = new SimpleClient();
		mapper = new ObjectMapper();
	}

	public void run() {
		app = Javalin.create().get("/", ctx -> ctx.status(200)).start(8080);
		app.post("/sendips", ctx -> {
			IPResponse res = mapper.readValue(ctx.body().toString(), new TypeReference<IPResponse>() {
			});
			if (ipValidation(res)) {
				ctx.status(client.openConnection(res.getIp(), res.getMask(), res.getThread_count()));
			} else {
				ctx.status(HttpStatus.BAD_REQUEST);
			}
		});
	}

	public void stop() {
		if (app != null)
			app.stop();
	}

	private boolean ipValidation(IPResponse res) {
		String ip = res.getIp();
		String mask = res.getMask();
		if (ip.isEmpty() || mask.isEmpty() || res.getThread_count() <= 0)
			return false;
		String octet = "(\\d{1,2}|(0|1)\\d{2}|2[0-4]\\d|25[0-5])";
		String regex_ip = octet + "\\." + octet + "\\." + octet + "\\." + octet;
		Pattern pat = Pattern.compile(regex_ip);
		int i_mask = Integer.valueOf(mask.substring(1));

		if (ip != null && i_mask >= 0 && i_mask <= 32) {
			Matcher matcher = pat.matcher(ip);
			if (matcher.matches())
				return true;
		}

		return false;
	}

}
