<template>
    <div>
      <h3>Requêtes possibles</h3>
      <button @click="getPcapData">Analyser le dernier fichier PCAP</button>
    </div>
  </template>
  
  <script>
  export default {
    methods: {
      async getPcapData() {
        this.$emit("request-sent", "analyse_pcap");
        try {
          const response = await this.$axios.get("http://localhost:8000/analyse_pcap");
          this.$emit("response-received", response.data);
        } catch (error) {
          this.$emit("response-received", { error: "Erreur lors de l'analyse du fichier PCAP" });
        }
      }
    }
  }
  </script>  