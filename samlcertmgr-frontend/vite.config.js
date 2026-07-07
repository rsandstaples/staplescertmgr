import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Builds straight into this module's own target/classes, so a plain `mvn
// package` here produces a jar containing assets/** on its classpath — no
// unpack or assembly step needed on the backend side. See frontend/pom.xml.
// Every backend endpoint — API, login, callback, logout — lives under /api/*
// (Dropwizard's server.rootPath), so a single proxy rule covers all of it in dev.
export default defineConfig({
	plugins: [react()],
	build: {
		outDir: "target/classes/assets",
		emptyOutDir: true,
	},
	server: {
		proxy: {
			"/api": "http://localhost:8080",
		},
	},
});