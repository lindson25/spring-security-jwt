package com.projetos.springsecurityjwt.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SessaoDTO {
    private String login;
    private String token;
}
