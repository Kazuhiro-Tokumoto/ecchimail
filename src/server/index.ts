import { ecchimailserverAPI } from "./api.js";

try {
    new ecchimailserverAPI(4000, "ecchi.manh2309.org", "localhost");
    console.log("起動した");
} catch (e) {
    console.error("エラー:", e);
}