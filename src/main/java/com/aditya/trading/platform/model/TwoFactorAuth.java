package com.aditya.trading.platform.model;

import com.aditya.trading.platform.domain.VerificationType;
import jakarta.persistence.Entity;
import lombok.*;


@Data
public class TwoFactorAuth {

    private boolean isEnabled = false ;

    private VerificationType sendTo ;
}
