import { cache } from "react";
import { cookies } from "next/headers";
import { SupabaseClient } from "@supabase/supabase-js";
import jwt from "jsonwebtoken";

import {
  AuthResponse,
  AuthTokens,
  SupabaseJwtPayload,
} from "./auth-manager-types";

import "server-only";

class AuthManager {
  private supabase: SupabaseClient;
  private jwtSecret: string;

  /**
   * Initializes the authentication manager with necessary dependencies.
   * @param supabase An instance of @supabase/ssr client
   * @param jwtSecret The secret used to verify JWTs.
   */
  constructor(supabase: SupabaseClient<any, any, any>, jwtSecret: string) {
    this.supabase = supabase;
    this.jwtSecret = jwtSecret;
  }

  /**
   * Retrieves authentication tokens from cookies.
   * @returns {AuthTokens | null} AuthTokens if found and correctly parsed, null otherwise.
   */
  private async getAuthTokensFromCookies(): Promise<AuthTokens | null> {
    console.log("Retrieving authentication tokens from cookies...");
    const cookieNameRegex = /^sb-[a-z]+-auth-token.*$/;
    const authCookies = (await cookies())
      .getAll()
      .filter((cookie) => cookieNameRegex.test(cookie.name))
      .sort((a, b) => a.name.localeCompare(b.name));
    console.log("Filtered auth cookies:", authCookies);

    if (!authCookies.length) {
      console.log("No authentication cookies found.");
      return null;
    }

    const authCookieValue = authCookies.map((cookie) => cookie.value).join("");

    try {
      const base64Value = decodeURIComponent(authCookieValue);
      const base64Prefix = "base64-";
      if (!base64Value.startsWith(base64Prefix)) {
        console.error("Auth cookie value does not start with 'base64-'");
        return null;
      }
      const base64Content = base64Value.slice(base64Prefix.length);
      const jsonString = Buffer.from(base64Content, "base64").toString("utf-8");
      const session = JSON.parse(jsonString);
      return {
        access_token: session.access_token,
        refresh_token: session.refresh_token,
      };
    } catch (error) {
      console.error("Error parsing auth cookie value:", error);
      return null;
    }
  }

  /**
   * Cached function to verify and parse the user session.
   * The cache is keyed by the access token, ensuring uniqueness per user.
   */
  private parseAndVerifySessionCached = cache(
    async (accessToken: string): Promise<AuthResponse> => {
      try {
        const session = jwt.verify(
          accessToken,
          this.jwtSecret
        ) as SupabaseJwtPayload;
        return { status: "success", data: { ...session, id: session.sub } };
      } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
          const tokens = { access_token: accessToken, refresh_token: "" };
          return this.refreshSession(tokens);
        } else {
          return { status: "error", error: "JWT verification failed" };
        }
      }
    }
  );

  /**
   * Verifies the JWT token, refreshes it if expired, and returns user data.
   * @returns {Promise<AuthResponse>} The user session data if successful, or an error message.
   */
  public async getSafeSession(): Promise<AuthResponse> {
    const tokens = await this.getAuthTokensFromCookies();
    if (!tokens) {
      return { status: "error", error: "Authentication tokens not found" };
    }
    // Use the cached function with the user's access token
    return this.parseAndVerifySessionCached(tokens.access_token);
  }

  /**
   * Refreshes the session when the JWT has expired.
   * @param tokens The authentication tokens.
   * @returns {Promise<AuthResponse>} The new session data or an error.
   */
  private async refreshSession(tokens: AuthTokens): Promise<AuthResponse> {
    const session = await this.supabase.auth.setSession(tokens);
    if (session.error) {
      return { status: "error", error: session.error.message };
    }
    if (!session.data || !session.data.user) {
      return {
        status: "error",
        error: "No user data available after refreshing session",
      };
    }
    return {
      status: "success",
      data: { ...session.data.user, sub: session.data.user.id },
    };
  }
}

export default AuthManager;
