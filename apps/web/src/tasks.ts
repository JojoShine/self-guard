export function taskParameters(values: Record<string, string>) {
  if(values.template==="SERVICE_STATE")return {service:values.service,expectedState:values.expectedState,state:values.serviceState};
  if (values.template === "CONFIG_VALUE")
    return {
      path: values.path,
      key: values.configKey,
      expectedValue: values.expectedValue,
      value: values.value,
      ...(values.healthService?{healthService:values.healthService}:{}),
    };
  return { path: values.path, mode: values.permission,...(values.healthService?{healthService:values.healthService}:{}) };
}
