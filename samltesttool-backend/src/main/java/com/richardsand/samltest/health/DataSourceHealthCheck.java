package com.richardsand.samltest.health;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import org.apache.commons.dbcp2.BasicDataSource;

import com.codahale.metrics.health.HealthCheck;

public class DataSourceHealthCheck extends HealthCheck {
    private final BasicDataSource dataSource;
    private final String          validationQuery;

    public DataSourceHealthCheck(BasicDataSource dataSource) {
        this(dataSource, "SELECT 1");
    }

    public DataSourceHealthCheck(BasicDataSource dataSource, String validationQuery) {
        this.dataSource = dataSource;
        this.validationQuery = validationQuery;
    }

    @Override
    protected Result check() {
        try (Connection conn = dataSource.getConnection();
                PreparedStatement stmt = conn.prepareStatement(validationQuery);
                ResultSet rs = stmt.executeQuery()) {

            if (rs.next()) {
                return Result.healthy("Database connection is valid");
            } else {
                return Result.unhealthy("Validation query returned no result");
            }
        } catch (Exception e) {
            return Result.unhealthy("Cannot connect to database: " + e.getMessage());
        }
    }
}
